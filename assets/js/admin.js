jQuery(document).ready(function($) {

    // --- Toast Notifications ---
    function showToast(message, type = 'success') {
        let toast = $('#metzler-webshield-toast');
        if (toast.length === 0) {
            toast = $('<div id="metzler-webshield-toast"></div>').appendTo('body');
        }
        toast.removeClass('toast-error').text(message);
        if (type === 'error') {
            toast.addClass('toast-error');
        }
        toast.stop(true, true).fadeIn(300).delay(4000).fadeOut(300);
    }

    // --- Clean Confirmation Modal ---
    function showConfirm(message, onConfirm, title) {
        title = title || (window.metzler_webshield_ajax && metzler_webshield_ajax.i18n && metzler_webshield_ajax.i18n.confirm_title ? metzler_webshield_ajax.i18n.confirm_title : 'Bestätigung erforderlich');
        let modal = $('#metzler-webshield-confirm-modal');
        if (modal.length === 0) {
            modal = $(`
                <div id="metzler-webshield-confirm-modal" style="display:none; position:fixed; inset:0; z-index:9999999; background:rgba(0,0,0,0.5); align-items:center; justify-content:center;">
                    <div style="background:#fff; border-radius:6px; max-width:420px; width:90%; padding:22px 24px; box-shadow:0 8px 24px rgba(0,0,0,0.2); border:1px solid #c3c4c7; box-sizing:border-box;">
                        <h3 class="metzler-modal-title" style="margin:0 0 10px 0; font-size:15px; font-weight:600; color:#1d2327;"></h3>
                        <p class="metzler-modal-body" style="margin:0 0 20px 0; font-size:13px; color:#50575e; line-height:1.5;"></p>
                        <div style="display:flex; justify-content:flex-end; gap:8px;">
                            <button type="button" class="button metzler-modal-cancel" style="min-height:30px;">Abbrechen</button>
                            <button type="button" class="button button-primary metzler-modal-confirm" style="min-height:30px;">Bestätigen</button>
                        </div>
                    </div>
                </div>
            `).appendTo('body');
        }
        modal.find('.metzler-modal-title').text(title);
        modal.find('.metzler-modal-body').text(message);
        modal.css('display', 'flex');

        modal.off('click', '.metzler-modal-confirm').on('click', '.metzler-modal-confirm', function() {
            modal.hide();
            if (typeof onConfirm === 'function') onConfirm();
        });
        modal.off('click', '.metzler-modal-cancel').on('click', '.metzler-modal-cancel', function() {
            modal.hide();
        });
    }

    let scanInProgress = false;
    
    let issuesFound = 0;
    
    let currentModule = '';
    let scanStartTime = 0;

    

    function setHeroStatus(status, title, subtitle) {
        const hero = $('#metzler-webshield-hero');
        const icon = hero.find('.hero-icon .dashicons');
        
        hero.removeClass('status-safe status-warning status-scanning status-loading');
        hero.addClass('status-' + status);
        
        icon.removeClass('dashicons-shield dashicons-shield-alt dashicons-warning');
        
        if (status === 'safe') {
            hero.removeClass('status-warning status-scanning status-loading').addClass('status-safe');
            icon.addClass('dashicons-shield');
        } else if (status === 'warning') {
            hero.removeClass('status-safe status-scanning status-loading').addClass('status-warning');
            icon.addClass('dashicons-warning');
        } else if (status === 'scanning') {
            hero.removeClass('status-safe status-warning status-loading').addClass('status-scanning');
            icon.addClass('dashicons-shield-alt');
        }
        
        if (title) $('#hero-title').text(title);
        if (subtitle) $('#hero-subtitle').text(subtitle);
    }

    

    function fetchLogs(callback) {
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_get_logs'
        }, function(response) {
            if (response.success && response.data.logs) {
                renderLogs(response.data.logs);
                const threats = response.data.logs.filter(l => l.severity === 'warning' || l.severity === 'error');
                
                let lastScanStart = 0;
                if (response.data.last_scan_start) {
                    lastScanStart = new Date(response.data.last_scan_start.replace(' ', 'T')).getTime();
                }
                
                const dashboardThreats = threats.filter(t => {
                    const logTime = new Date(t.time.replace(' ', 'T')).getTime();
                    return logTime >= lastScanStart;
                });
                
                issuesFound = dashboardThreats.length;
                
                // Update active threats UI on dashboard
                if (issuesFound > 0) {
                    $('#active-threats-list').empty();
                    dashboardThreats.slice(0, 5).forEach(t => {
                        $('#active-threats-list').append('<li style="margin-bottom:10px;">' + t.message + '</li>');
                    });
                    if (dashboardThreats.length > 5) {
                        $('#active-threats-list').append('<li><em>' + metzler_webshield_ajax.i18n.more_logs.replace('%d', dashboardThreats.length - 5) + '</em></li>');
                    }
                    $('#metzler-webshield-active-threats').show();
                } else {
                    $('#metzler-webshield-active-threats').hide();
                }
                
                if (scanInProgress && issuesFound > 0) {
                    setHeroStatus('warning', metzler_webshield_ajax.i18n.hero_risks, metzler_webshield_ajax.i18n.hero_risks_scan);
                }
                
                // Set initial board state properly
                if (!scanInProgress) {
                    if (issuesFound > 0) {
                        setHeroStatus('warning', metzler_webshield_ajax.i18n.hero_risks, metzler_webshield_ajax.i18n.hero_check_log);
                    } else {
                        setHeroStatus('safe', (metzler_webshield_ajax.is_licensed ?  metzler_webshield_ajax.i18n.hero_secure : metzler_webshield_ajax.i18n.hero_local_secure), (metzler_webshield_ajax.is_licensed ?  metzler_webshield_ajax.i18n.hero_guards_active : metzler_webshield_ajax.i18n.hero_local_desc));
                    }
                }
            }
            if (callback) callback();
        });
    }

    function renderLogs(logs) {
        const tbody = $('#metzler-webshield-log-body');
        tbody.empty();
        
        if (!logs || logs.length === 0) {
            tbody.append('<tr><td colspan="3" style="text-align:center;">' + metzler_webshield_ajax.i18n.log_empty + '</td></tr>');
            return;
        }

        logs.forEach(log => {
            let timeStr = log.time || '';
            try {
                if (log.time) {
                    const dateObj = new Date(log.time.replace(' ', 'T'));
                    if (!isNaN(dateObj.getTime())) {
                        timeStr = dateObj.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    }
                }
            } catch (e) {
                timeStr = log.time;
            }

            const trClass = 'metzler-webshield-row-' + (log.severity || 'info');
            const tr = `<tr class="${trClass}">
                <td>${timeStr}</td>
                <td><span class="metzler-webshield-log-module">${log.type || 'system'}</span></td>
                <td class="metzler-webshield-log-severity-${log.severity || 'info'}">${log.message}</td>
            </tr>`;
            tbody.append(tr);
        });
    }

    $(document).on('click', '.metzler-webshield-update-btn', function(e) {
        e.preventDefault();
        const btn = $(this);
        const updateType = btn.data('update-type');
        const updateItem = btn.data('update-item');
        
        btn.prop('disabled', true).text(metzler_webshield_ajax.i18n.updating);
        
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_do_update',
            update_type: updateType,
            update_item: updateItem
        }, function(response) {
            if (response.success) {
                btn.replaceWith('<span style="color:#00a32a;">' + metzler_webshield_ajax.i18n.update_success + '</span>');
                issuesFound = Math.max(0, issuesFound - 1);
                if (issuesFound === 0) {
                    setHeroStatus('safe', (metzler_webshield_ajax.is_licensed ?  metzler_webshield_ajax.i18n.hero_secure : metzler_webshield_ajax.i18n.hero_local_secure), metzler_webshield_ajax.i18n.hero_issues_fixed);
                }
            } else {
                btn.text(metzler_webshield_ajax.i18n.update_error);
                showToast(response.data.message || metzler_webshield_ajax.i18n.generic_error, 'error');
            }
        });
    });

    function processQueue() {
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_process_queue'
        }, function(response) {
            if (response.success) {
                if (response.data.status === 'processing') {
                    $('#scan-status-text').text(response.data.message);
                    currentModule = response.data.task;
                    updateScanStage(currentModule);
                    
                    let w = parseInt($('#scan-progress-fill').css('width')) / $('#scan-progress-fill').parent().width() * 100;
                    if (w < 95) $('#scan-progress-fill').css('width', (w + 2) + '%');
                    
                    $('#scan-eta').hide();

                    fetchLogs();
                    setTimeout(processQueue, 300);
                } else if (response.data.status === 'complete') {
                    finishScan();
                }
            } else {
                $('#scan-status-text').text(metzler_webshield_ajax.i18n.scan_aborted_msg + response.data.message);
                finishScan();
            }
        }).fail(function() {
            $('#scan-status-text').text(metzler_webshield_ajax.i18n.connection_error);
            setTimeout(processQueue, 2000);
        });
    }

    function updateScanStage(currentTask) {
        const stagesOrder = ['init', 'scan_updates', 'scan_plugins', 'scan_core', 'scan_files', 'scan_fim', 'scan_config'];
        const isLicensed = metzler_webshield_ajax.is_licensed;
        
        if (currentTask === 'complete') {
            $('.scan-stage').show().removeClass('active').addClass('completed');
            
            if (!isLicensed) {
                $('.scan-stage[data-stage="scan_plugins"], .scan-stage[data-stage="scan_core"]')
                    .removeClass('completed active')
                    .addClass('skipped')
                    .find('.stage-text').html(function(_, oldHtml) {
                        return oldHtml.indexOf('Skipped') === -1 ? oldHtml + ' <i>(Skipped - Free Cloud License required)</i>' : oldHtml;
                    });
            }
            
            $('.scan-stage[data-stage="complete"]').show();
            return;
        }

        let foundCurrent = false;
        stagesOrder.forEach(function(stage) {
            const el = $('.scan-stage[data-stage="' + stage + '"]');
            
            if (!isLicensed && (stage === 'scan_plugins' || stage === 'scan_core')) {
                el.show().removeClass('active completed').addClass('skipped');
                el.find('.stage-text').html(function(_, oldHtml) {
                    return oldHtml.indexOf('Skipped') === -1 ? oldHtml + ' <i>(Skipped - Free Cloud License required)</i>' : oldHtml;
                });
                return;
            }

            if (stage === currentTask) {
                foundCurrent = true;
                el.show().removeClass('completed skipped').addClass('active');
            } else if (!foundCurrent) {
                el.show().removeClass('active skipped').addClass('completed');
            } else {
                el.show().removeClass('active completed skipped');
            }
        });
        $('.scan-stage[data-stage="complete"]').hide();
    }

    $('#btn-start-scan').on('click', function() {
        if(scanInProgress) return;
        scanInProgress = true;
        
        $('#metzler-webshield-scan-controls').hide();
        $('#scan-progress-wrapper').show();
        $('#btn-cancel-scan').show();
        $('#scan-progress-fill').css('width', '5%');
        $('#scan-status-text').text(metzler_webshield_ajax.i18n.init_scan);
        
        updateScanStage('init');
        
        setHeroStatus('scanning', metzler_webshield_ajax.i18n.hero_scan_running, metzler_webshield_ajax.i18n.hero_scan_desc);
        
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_start_scan'
        }, function(response) {
            if(response.success) {
                scanStartTime = Date.now();
                processQueue();
                
            } else {
                scanInProgress = false;
                $('#scan-progress-wrapper').hide();
                $('#btn-cancel-scan').hide();
                $('#metzler-webshield-scan-controls').show();
                fetchLogs();
                showToast(response.data ? response.data.message : 'Error starting scan', 'error');
            }
        });
    });

    $('#btn-cancel-scan').on('click', function(e) {
        e.preventDefault();
        showConfirm(metzler_webshield_ajax.i18n.confirm_cancel_scan, function() {
            scanInProgress = false;
            $('#btn-cancel-scan').hide();
            $('#scan-progress-wrapper').hide();
            $('#metzler-webshield-scan-controls').show();
            
            $.post(metzler_webshield_ajax.ajax_url, {
                _wpnonce: metzler_webshield_ajax.nonce,
                action: 'metzler_webshield_cancel_scan'
            }, function(response) {
                setHeroStatus('warning', metzler_webshield_ajax.i18n.hero_scan_aborted, metzler_webshield_ajax.i18n.hero_aborted_desc);
                fetchLogs();
            });
        });
    });

    function finishScan() {
        scanInProgress = false;
        
        
        $('#scan-eta').hide();
        $('#btn-cancel-scan').hide();
        
        $('#scan-progress-fill').css('width', '100%');
        updateScanStage('complete');
        
        const now = new Date().toLocaleString();
        $('#stat-last-scan').text(now);
        
        fetchLogs(function() {
            setTimeout(() => {
                $('#scan-progress-wrapper').slideUp();
                $('#metzler-webshield-scan-controls').slideDown();
                
                if (issuesFound > 0) {
                    setHeroStatus('warning', metzler_webshield_ajax.i18n.hero_risks, metzler_webshield_ajax.i18n.hero_issues_found);
                } else {
                    setHeroStatus('safe', (metzler_webshield_ajax.is_licensed ?  metzler_webshield_ajax.i18n.hero_secure : metzler_webshield_ajax.i18n.hero_local_secure), metzler_webshield_ajax.i18n.hero_no_threats);
                }
            }, 1000);
        });
    }

    $('#btn-refresh-logs').on('click', fetchLogs);
    
    $('#btn-clear-logs').on('click', function() {
        showConfirm(metzler_webshield_ajax.i18n.confirm_clear_log, function() {
            $.post(metzler_webshield_ajax.ajax_url, {
                _wpnonce: metzler_webshield_ajax.nonce,
                action: 'metzler_webshield_clear_logs'
            }, function(response) {
                if(response.success) {
                    fetchLogs(function() {
                        setHeroStatus('safe', (metzler_webshield_ajax.is_licensed ?  metzler_webshield_ajax.i18n.hero_secure : metzler_webshield_ajax.i18n.hero_local_secure), metzler_webshield_ajax.i18n.hero_log_cleared);
                        issuesFound = 0;
                    });
                }
            });
        });
    });
    
    $('#btn-create-baseline').on('click', function() {
        const btn = $(this);
        btn.prop('disabled', true).text(metzler_webshield_ajax.i18n.creating_baseline);
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_create_baseline'
        }, function(response) {
            if(response.success) {
                showToast(response.data.message);
                fetchLogs();
            }
            btn.prop('disabled', false).text(metzler_webshield_ajax.i18n.set_fim_baseline);
        });
    });

    // --- UX Buttons (Safe & Quarantine) ---
    $(document).on('click', '.metzler-webshield-q-safe', function(e) {
        e.preventDefault();
        const btn = $(this);
        const path = btn.data('path');
        btn.text(metzler_webshield_ajax.i18n.saving);
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_accept_fim',
            path: path
        }, function(response) {
            if(response.success) {
                btn.closest('td').append('<span style="color:green;"> ' + metzler_webshield_ajax.i18n.marked_safe + '</span>');
                btn.siblings('.metzler-webshield-q-move').remove();
                btn.remove();
                fetchLogs(); // UI dynamisch aktualisieren
            }
        });
    });

    $(document).on('click', '.metzler-webshield-delete-user', function(e) {
        e.preventDefault();
        const btn = $(this);
        const userId = btn.data('user-id');
        showConfirm(metzler_webshield_ajax.i18n.delete_confirm, function() {
            btn.prop('disabled', true).text(metzler_webshield_ajax.i18n.deleting);
            $.post(metzler_webshield_ajax.ajax_url, {
                _wpnonce: metzler_webshield_ajax.nonce,
                action: 'metzler_webshield_delete_user',
                user_id: userId
            }, function(response) {
                if(response.success) {
                    btn.closest('td').append('<span style="color:green;"> ' + metzler_webshield_ajax.i18n.deleted_ghost + '</span>');
                    btn.remove();
                    fetchLogs();
                } else {
                    showToast(response.data.message || metzler_webshield_ajax.i18n.delete_error, 'error');
                    btn.prop('disabled', false).text(metzler_webshield_ajax.i18n.delete_user);
                }
            });
        });
    });

    $(document).on('click', '.metzler-webshield-q-move', function(e) {
        e.preventDefault();
        const btn = $(this);
        const path = btn.data('path');
        btn.text(metzler_webshield_ajax.i18n.moving);
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_quarantine_file',
            path: path
        }, function(response) {
            if(response.success) {
                btn.closest('td').append('<span style="color:green;"> ' + metzler_webshield_ajax.i18n.moved_quarantine + '</span>');
                btn.siblings('.metzler-webshield-q-safe').remove();
                btn.remove();
                loadQuarantine();
                fetchLogs(); // UI dynamisch aktualisieren
            } else {
                showToast(response.data.message || metzler_webshield_ajax.i18n.move_error, 'error');
                btn.text(metzler_webshield_ajax.i18n.move_to_quarantine);
            }
        });
    });

    // --- Tab Switching & Deep Linking ---
    function normalizeTabId(rawId) {
        if (!rawId) return '';
        var clean = String(rawId).replace(/^#/, '').trim().toLowerCase();
        var aliases = {
            'overview': 'tab-dashboard',
            'dashboard': 'tab-dashboard',
            'tab-overview': 'tab-dashboard',
            'tab-dashboard': 'tab-dashboard',
            'log': 'tab-logs',
            'logs': 'tab-logs',
            'tab-log': 'tab-logs',
            'tab-logs': 'tab-logs',
            'quarantine': 'tab-quarantine',
            'tab-quarantine': 'tab-quarantine',
            'setting': 'tab-settings',
            'settings': 'tab-settings',
            'tab-setting': 'tab-settings',
            'tab-settings': 'tab-settings',
            'license': 'tab-license',
            'licence': 'tab-license',
            'tab-license': 'tab-license',
            'tab-licence': 'tab-license'
        };

        if (aliases[clean]) {
            return aliases[clean];
        }

        if (clean.indexOf('tab-') !== 0) {
            clean = 'tab-' + clean;
        }
        return clean;
    }

    function switchTab(targetTab, updateHash) {
        var normalized = normalizeTabId(targetTab);
        var tabContent = $('#' + normalized);
        var tabLink = $('.metzler-webshield-tab-link[data-tab="' + normalized + '"]');

        if (tabContent.length === 0) {
            return false;
        }

        $('.metzler-webshield-tab-link').removeClass('nav-tab-active');
        tabLink.addClass('nav-tab-active');

        $('.metzler-webshield-tab-content').hide();
        tabContent.show();

        if (updateHash !== false) {
            if (window.history && window.history.replaceState) {
                var newUrl = window.location.pathname + window.location.search + '#' + normalized;
                window.history.replaceState(null, '', newUrl);
            } else {
                window.location.hash = normalized;
            }
        }

        if (normalized === 'tab-logs') {
            fetchLogs();
        }

        if (normalized === 'tab-quarantine') {
            loadQuarantine();
        }

        return true;
    }

    $('.metzler-webshield-tab-link').on('click', function(e) {
        e.preventDefault();
        var targetTab = $(this).data('tab') || $(this).attr('href');
        switchTab(targetTab, true);
    });

    $(document).on('click', 'a[href^="#tab-"], a[href^="#logs"], a[href^="#quarantine"], a[href^="#settings"], a[href^="#license"], a[href^="#overview"]', function(e) {
        var href = $(this).attr('href');
        if (switchTab(href, true)) {
            e.preventDefault();
        }
    });

    // Check initial tab on page load
    function checkInitialTab() {
        if (window.location.hash) {
            switchTab(window.location.hash, false);
        } else {
            var urlParams = new URLSearchParams(window.location.search);
            if (urlParams.has('tab')) {
                switchTab(urlParams.get('tab'), false);
            }
        }
    }
    checkInitialTab();
    fetchLogs();

    // Listen for browser back/forward or manual hash change
    $(window).on('hashchange', function() {
        if (window.location.hash) {
            switchTab(window.location.hash, false);
        }
    });

    // --- Quarantine ---
    function loadQuarantine() {
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_get_quarantine'
        }, function(response) {
            if(response.success && response.data.files) {
                const tbody = $('#metzler-webshield-quarantine-body');
                tbody.empty();
                if(response.data.files.length === 0) {
                    tbody.append('<tr><td colspan="3">' + metzler_webshield_ajax.i18n.quarantine_empty + '</td></tr>');
                    return;
                }
                
                response.data.files.forEach(function(f) {
                    let html = '<tr>';
                    html += '<td>' + f.time + '</td>';
                    html += '<td>' + f.original_path + '</td>';
                    html += '<td>';
                    html += '<button type="button" class="button button-small metzler-webshield-q-restore" data-id="' + f.id + '">' + metzler_webshield_ajax.i18n.restore + '</button> ';
                    html += '<button type="button" class="button button-small metzler-webshield-q-delete" data-id="' + f.id + '" style="color:#d63638;">' + metzler_webshield_ajax.i18n.delete_permanent + '</button>';
                    html += '</td></tr>';
                    tbody.append(html);
                });
            }
        });
    }

    $(document).on('click', '.metzler-webshield-q-restore', function() {
        const id = $(this).data('id');
        $(this).text(metzler_webshield_ajax.i18n.restoring);
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_quarantine_restore', id: id }, function(res) {
            if(res.success) {
                loadQuarantine();
                showToast(metzler_webshield_ajax.i18n.file_restored);
            }
        });
    });

    $(document).on('click', '.metzler-webshield-q-delete', function() {
        const id = $(this).data('id');
        showConfirm(metzler_webshield_ajax.i18n.confirm_delete, function() {
            $.post(metzler_webshield_ajax.ajax_url, {
                _wpnonce: metzler_webshield_ajax.nonce,
                action: 'metzler_webshield_quarantine_delete', id: id }, function(res) {
                if(res.success) loadQuarantine();
            });
        });
    });
    
    // --- Settings ---
    $('#btn-save-settings').on('click', function() {
        const btn = $(this);
        const fimEnabled = $('#metzler-webshield-setting-fim').is(':checked') ? '1' : '0';
        const coreEnabled = $('#metzler-webshield-setting-core').is(':checked') ? '1' : '0';
        const filesEnabled = $('#metzler-webshield-setting-files').is(':checked') ? '1' : '0';
        const updatesEnabled = $('#metzler-webshield-setting-updates').is(':checked') ? '1' : '0';
        const pluginsEnabled = $('#metzler-webshield-setting-plugins').is(':checked') ? '1' : '0';
        const wafEnabled = $('#metzler-webshield-setting-waf').is(':checked') ? '1' : '0';
        const xmlrpcDisabled = $('#metzler-webshield-setting-xmlrpc').is(':checked') ? '1' : '0';
        const ratelimitEnabled = $('#metzler-webshield-setting-ratelimit').is(':checked') ? '1' : '0';
        const underAttackEnabled = $('#metzler-webshield-setting-under-attack').is(':checked') ? '1' : '0';
        const telemetryEnabled = $('#metzler-webshield-setting-telemetry').is(':checked') ? '1' : '0';
        btn.prop('disabled', true);
        
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_save_settings',
            enable_fim: fimEnabled,
            enable_core: coreEnabled,
            enable_files: filesEnabled,
            enable_updates: updatesEnabled,
            enable_plugins: pluginsEnabled,
            enable_waf: wafEnabled,
            disable_xmlrpc: xmlrpcDisabled,
            enable_ratelimit: ratelimitEnabled,
            under_attack_mode: underAttackEnabled,
            enable_telemetry: telemetryEnabled
        }, function(res) {
            btn.prop('disabled', false);
            if(res.success) {
                $('#settings-save-feedback').show().fadeOut(3000);
                setTimeout(function(){ location.reload(); }, 1000); // Reload to show MU-plugin status
            }
        });
    });
    
    $('#btn-rebuild-fim').on('click', function(e) {
        e.preventDefault();
        const btn = $(this);
        const feedback = $('#fim-rebuild-feedback');
        btn.prop('disabled', true);
        feedback.text(metzler_webshield_ajax.i18n.reading_files);
        
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_create_baseline'
        }, function(res) {
            btn.prop('disabled', false);
            if(res.success) {
                feedback.css('color', 'green').text(metzler_webshield_ajax.i18n.success + res.data.message);
                setTimeout(() => feedback.text(''), 4000);
            } else {
                feedback.css('color', 'red').text(metzler_webshield_ajax.i18n.read_error);
            }
        });
    });

    // --- Licensing ---
    $('#metzler-webshield-license-email').on('keypress', function(e) {
        if (e.which === 13) {
            e.preventDefault();
            $('#btn-request-license').click();
        }
    });

    $('#metzler-webshield-license-token').on('keypress', function(e) {
        if (e.which === 13) {
            e.preventDefault();
            $('#btn-verify-license').click();
        }
    });

    $('#btn-request-license').on('click', function() {
        const btn = $(this);
        const email = $('#metzler-webshield-license-email').val();
        const feedback = $('#license-request-feedback');

        if (!email) {
            feedback.css('color', 'red').text(metzler_webshield_ajax.i18n.enter_email);
            return;
        }

        btn.prop('disabled', true).text(metzler_webshield_ajax.i18n.requesting);
        feedback.text('');

        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_request_license',
            email: email
        }, function(res) {
            btn.prop('disabled', false).text(metzler_webshield_ajax.i18n.request_key);
            if (res.success) {
                feedback.css('color', 'green').text(res.data.message);
            } else {
                feedback.css('color', 'red').text(res.data.message || metzler_webshield_ajax.i18n.request_error);
            }
        });
    });

    $('#btn-verify-license').on('click', function() {
        const btn = $(this);
        const token = $('#metzler-webshield-license-token').val();
        const email = $('#metzler-webshield-license-email').val();
        const telemetry = $('#metzler-webshield-license-telemetry').is(':checked') ? '1' : '0';
        const feedback = $('#license-verify-feedback');

        if (!token) {
            feedback.css('color', 'red').text(metzler_webshield_ajax.i18n.enter_key);
            return;
        }

        btn.prop('disabled', true).text(metzler_webshield_ajax.i18n.verifying);
        feedback.text('');

        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_verify_license',
            token: token,
            email: email,
            telemetry: telemetry
        }, function(res) {
            if (res.success) {
                feedback.css('color', 'green').text(res.data.message);
                setTimeout(function(){ location.reload(); }, 1500);
            } else {
                btn.prop('disabled', false).text(metzler_webshield_ajax.i18n.verify_license);
                feedback.css('color', 'red').text(res.data.message || metzler_webshield_ajax.i18n.invalid_key);
            }
        });
    });

    $(document).on('click', '#btn-recheck-license, .btn-recheck-license', function() {
        const btn = $(this);
        const feedback = btn.siblings('.metzler-webshield-action-feedback');
        btn.prop('disabled', true).text(metzler_webshield_ajax.i18n.rechecking);
        
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_recheck_license'
        }, function(res) {
            if (res.success) {
                feedback.css('color', 'green').text(metzler_webshield_ajax.i18n.license_valid);
                setTimeout(function(){ location.reload(); }, 1200);
            } else {
                showToast(metzler_webshield_ajax.i18n.license_invalid, 'error');
                setTimeout(function(){ location.reload(); }, 2000);
            }
        });
    });

    $(document).on('click', '#btn-remove-license, .btn-remove-license', function() {
        showConfirm(metzler_webshield_ajax.i18n.confirm_remove, function() {
            $.post(metzler_webshield_ajax.ajax_url, {
                _wpnonce: metzler_webshield_ajax.nonce,
                action: 'metzler_webshield_remove_license'
            }, function(res) {
                location.reload();
            });
        });
    });
    // Initial Load handled via PHP SSR for better performance
});







