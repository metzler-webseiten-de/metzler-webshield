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
                        $('#active-threats-list').append('<li><em>... und ' + (dashboardThreats.length - 5) + ' weitere (siehe Protokoll).</em></li>');
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
        
        if (logs.length === 0) {
            tbody.append('<tr><td colspan="3" style="text-align:center;">Das Protokoll ist leer.</td></tr>');
            return;
        }

        logs.forEach(log => {
            const time = new Date(log.time).toLocaleTimeString();
            const trClass = 'metzler-webshield-row-' + log.severity;
            const tr = `<tr class="${trClass}">
                <td>${time}</td>
                <td><span class="metzler-webshield-log-module">${log.type}</span></td>
                <td class="metzler-webshield-log-severity-${log.severity}">${log.message}</td>
            </tr>`;
            tbody.append(tr);
        });
    }

    $(document).on('click', '.metzler-webshield-update-btn', function(e) {
        e.preventDefault();
        const btn = $(this);
        const updateType = btn.data('update-type');
        const updateItem = btn.data('update-item');
        
        btn.prop('disabled', true).text('Aktualisiere...');
        
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_do_update',
            update_type: updateType,
            update_item: updateItem
        }, function(response) {
            if (response.success) {
                btn.replaceWith('<span style="color:#00a32a;">✔ Erfolgreich aktualisiert</span>');
                issuesFound = Math.max(0, issuesFound - 1);
                if (issuesFound === 0) {
                    setHeroStatus('safe', (metzler_webshield_ajax.is_licensed ?  metzler_webshield_ajax.i18n.hero_secure : metzler_webshield_ajax.i18n.hero_local_secure), metzler_webshield_ajax.i18n.hero_issues_fixed);
                }
            } else {
                btn.text('Fehler beim Update');
                showToast(response.data.message || 'Ein Fehler ist aufgetreten.', 'error');
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
                $('#scan-status-text').text('Scan abgebrochen: ' + response.data.message);
                finishScan();
            }
        }).fail(function() {
            $('#scan-status-text').text('Verbindungsproblem. Wiederhole...');
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
        if(!confirm(metzler_webshield_ajax.i18n.confirm_cancel_scan)) return;
        scanInProgress = false;
        $(this).hide();
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
        if(confirm(metzler_webshield_ajax.i18n.confirm_clear_log)) {
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
        }
    });
    
    $('#btn-create-baseline').on('click', function() {
        const btn = $(this);
        btn.prop('disabled', true).text('Erstelle Baseline...');
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_create_baseline'
        }, function(response) {
            if(response.success) {
                showToast(response.data.message);
                fetchLogs();
            }
            btn.prop('disabled', false).text('FIM Baseline setzen');
        });
    });

    // --- UX Buttons (Safe & Quarantine) ---
    $(document).on('click', '.metzler-webshield-q-safe', function(e) {
        e.preventDefault();
        const btn = $(this);
        const path = btn.data('path');
        btn.text('Speichere...');
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

    // --- Tab Switching ---
    $('.metzler-webshield-tab-link').on('click', function(e) {
        e.preventDefault();
        const targetTab = $(this).data('tab');

        $('.metzler-webshield-tab-link').removeClass('nav-tab-active');
        $(this).addClass('nav-tab-active');
        
        $('.metzler-webshield-tab-content').hide();
        $('#' + targetTab).show();
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
        if(!confirm(metzler_webshield_ajax.i18n.confirm_delete)) return;
        const id = $(this).data('id');
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_quarantine_delete', id: id }, function(res) {
            if(res.success) loadQuarantine();
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
            email: email
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

    $('#btn-recheck-license').on('click', function() {
        const btn = $(this);
        const feedback = $('#license-recheck-feedback');
        btn.prop('disabled', true).text(metzler_webshield_ajax.i18n.rechecking);
        
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_recheck_license'
        }, function(res) {
            if (res.success) {
                feedback.css('color', 'green').text(metzler_webshield_ajax.i18n.license_valid);
                setTimeout(function(){ feedback.text(''); btn.prop('disabled', false).text(metzler_webshield_ajax.i18n.recheck_now); }, 3000);
            } else {
                showToast(metzler_webshield_ajax.i18n.license_invalid, 'error');
                setTimeout(function(){ location.reload(); }, 2000);
            }
        });
    });

    $('#btn-remove-license').on('click', function() {
        if (!confirm(metzler_webshield_ajax.i18n.confirm_remove)) return;
        
        $.post(metzler_webshield_ajax.ajax_url, {
            _wpnonce: metzler_webshield_ajax.nonce,
            action: 'metzler_webshield_remove_license'
        }, function(res) {
            location.reload();
        });
    });
    // Initial Load handled via PHP SSR for better performance
});







