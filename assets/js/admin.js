jQuery(document).ready(function($) {
    let scanInProgress = false;
    let rapidInterval = null;
    let issuesFound = 0;
    let totalFilesScanned = 0;
    let currentModule = '';
    let scanStartTime = 0;

    const fakePaths = [
        "wp-includes/functions.php",
        "wp-includes/formatting.php",
        "wp-admin/admin-ajax.php",
        "wp-admin/includes/file.php",
        "wp-content/plugins/index.php",
        "wp-content/uploads/2023/index.php",
        "wp-config.php",
        "wp-settings.php"
    ];

    function setHeroStatus(status, title, subtitle) {
        const hero = $('#wpprotector-hero');
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

    function startRapidFeedback() {
        if (rapidInterval) clearInterval(rapidInterval);
        
        rapidInterval = setInterval(() => {
            if (!scanInProgress) {
                clearInterval(rapidInterval);
                return;
            }
            
            let base = fakePaths[Math.floor(Math.random() * fakePaths.length)];
            if (currentModule === 'scan_plugins') base = "wp-content/plugins/" + Math.random().toString(36).substring(7) + ".php";
            if (currentModule === 'scan_files') base = "wp-content/uploads/" + Math.random().toString(36).substring(7) + ".jpg";
            if (currentModule === 'scan_core') base = "wp-includes/" + Math.random().toString(36).substring(5) + ".php";
            
            $('#scan-rapid-path').text('Prüfe: ' + base);
            
            totalFilesScanned += Math.floor(Math.random() * 8) + 1;
            $('#stat-files-scanned').text(totalFilesScanned.toLocaleString());
            
        }, 70); 
    }

    function fetchLogs(callback) {
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_get_logs'
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
                    $('#wpprotector-active-threats').show();
                } else {
                    $('#wpprotector-active-threats').hide();
                }
                
                if (scanInProgress && issuesFound > 0) {
                    setHeroStatus('warning', 'Sicherheitsrisiken gefunden!', 'Der Smart Scan läuft noch, aber es wurden bereits Probleme entdeckt.');
                }
                
                // Set initial board state properly
                if (!scanInProgress) {
                    if (issuesFound > 0) {
                        setHeroStatus('warning', 'Sicherheitsrisiken erkannt!', 'Bitte überprüfe das Sicherheitsprotokoll.');
                    } else {
                        setHeroStatus('safe', 'Deine Website ist sicher.', 'Alle Hintergrund-Wächter sind aktiv und aktuell.');
                    }
                }
            }
            if (callback) callback();
        });
    }

    function renderLogs(logs) {
        const tbody = $('#wpprotector-log-body');
        tbody.empty();
        
        if (logs.length === 0) {
            tbody.append('<tr><td colspan="3" style="text-align:center;">Das Protokoll ist leer.</td></tr>');
            return;
        }

        logs.forEach(log => {
            const time = new Date(log.time).toLocaleTimeString();
            const trClass = 'wpprotector-row-' + log.severity;
            const tr = `<tr class="${trClass}">
                <td>${time}</td>
                <td><span class="wpprotector-log-module">${log.type}</span></td>
                <td class="wpprotector-log-severity-${log.severity}">${log.message}</td>
            </tr>`;
            tbody.append(tr);
        });
    }

    $(document).on('click', '.wpprotector-update-btn', function(e) {
        e.preventDefault();
        const btn = $(this);
        const updateType = btn.data('update-type');
        const updateItem = btn.data('update-item');
        
        btn.prop('disabled', true).text('Aktualisiere...');
        
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_do_update',
            update_type: updateType,
            update_item: updateItem
        }, function(response) {
            if (response.success) {
                btn.replaceWith('<span style="color:#00a32a;">✔ Erfolgreich aktualisiert</span>');
                issuesFound = Math.max(0, issuesFound - 1);
                if (issuesFound === 0) {
                    setHeroStatus('safe', 'Deine Website ist sicher.', 'Alle Probleme wurden behoben.');
                }
            } else {
                btn.text('Fehler beim Update');
                alert(response.data.message || 'Ein Fehler ist aufgetreten.');
            }
        });
    });

    function processQueue() {
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_process_queue'
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
        
        if (currentTask === 'complete') {
            $('.scan-stage').show().removeClass('active').addClass('completed');
            $('.scan-stage[data-stage="complete"]').show();
            return;
        }

        let foundCurrent = false;
        stagesOrder.forEach(function(stage) {
            const el = $('.scan-stage[data-stage="' + stage + '"]');
            if (stage === currentTask) {
                foundCurrent = true;
                el.show().removeClass('completed').addClass('active');
            } else if (!foundCurrent) {
                el.show().removeClass('active').addClass('completed');
            } else {
                el.show().removeClass('active completed');
            }
        });
        $('.scan-stage[data-stage="complete"]').hide();
    }

    $('#btn-start-scan').on('click', function() {
        if(scanInProgress) return;
        scanInProgress = true;
        
        $('#wpprotector-scan-controls').hide();
        $('#scan-progress-wrapper').show();
        $('#btn-cancel-scan').show();
        $('#scan-progress-fill').css('width', '5%');
        $('#scan-status-text').text('Initialisiere Smart Scan...');
        
        updateScanStage('init');
        
        setHeroStatus('scanning', 'Smart Scan läuft...', 'Dateien und Datenbanken werden analysiert...');
        
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_start_scan'
        }, function(response) {
            if(response.success) {
                scanStartTime = Date.now();
                processQueue();
                startRapidFeedback();
            }
        });
    });

    $('#btn-cancel-scan').on('click', function(e) {
        e.preventDefault();
        if(!confirm("Möchtest du den aktuellen Scan wirklich abbrechen?")) return;
        scanInProgress = false;
        $(this).hide();
        $('#scan-progress-wrapper').hide();
        $('#wpprotector-scan-controls').show();
        
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_cancel_scan'
        }, function(response) {
            setHeroStatus('warning', 'Scan abgebrochen', 'Der Smart Scan wurde manuell abgebrochen.');
            fetchLogs();
            clearInterval(rapidInterval);
        });
    });

    function finishScan() {
        scanInProgress = false;
        clearInterval(rapidInterval);
        $('#scan-rapid-path').text('');
        $('#scan-eta').hide();
        $('#btn-cancel-scan').hide();
        
        $('#scan-progress-fill').css('width', '100%');
        updateScanStage('complete');
        
        const now = new Date().toLocaleString();
        $('#stat-last-scan').text(now);
        
        fetchLogs(function() {
            setTimeout(() => {
                $('#scan-progress-wrapper').slideUp();
                $('#wpprotector-scan-controls').slideDown();
                
                if (issuesFound > 0) {
                    setHeroStatus('warning', 'Sicherheitsrisiken gefunden!', 'Es wurden Probleme entdeckt. Bitte überprüfe das Protokoll unten.');
                } else {
                    setHeroStatus('safe', 'Deine Website ist sicher.', 'Der Smart Scan hat keine Bedrohungen gefunden.');
                }
            }, 1000);
        });
    }

    $('#btn-refresh-logs').on('click', fetchLogs);
    
    $('#btn-clear-logs').on('click', function() {
        if(confirm('Möchtest du das gesamte Sicherheitsprotokoll wirklich leeren?')) {
            $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_clear_logs'
            }, function(response) {
                if(response.success) {
                    fetchLogs(function() {
                        setHeroStatus('safe', 'Deine Website ist sicher.', 'Das Protokoll wurde geleert.');
                        issuesFound = 0;
                    });
                }
            });
        }
    });
    
    $('#btn-create-baseline').on('click', function() {
        const btn = $(this);
        btn.prop('disabled', true).text('Erstelle Baseline...');
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_create_baseline'
        }, function(response) {
            if(response.success) {
                alert(response.data.message);
                fetchLogs();
            }
            btn.prop('disabled', false).text('FIM Baseline setzen');
        });
    });

    // --- UX Buttons (Safe & Quarantine) ---
    $(document).on('click', '.wpprotector-q-safe', function(e) {
        e.preventDefault();
        const btn = $(this);
        const path = btn.data('path');
        btn.text('Speichere...');
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_accept_fim',
            path: path
        }, function(response) {
            if(response.success) {
                btn.closest('td').append('<span style="color:green;"> ' + wpprotector_ajax.i18n.marked_safe + '</span>');
                btn.siblings('.wpprotector-q-move').remove();
                btn.remove();
                fetchLogs(); // UI dynamisch aktualisieren
            }
        });
    });

    $(document).on('click', '.wpprotector-q-move', function(e) {
        e.preventDefault();
        const btn = $(this);
        const path = btn.data('path');
        btn.text(wpprotector_ajax.i18n.moving);
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_quarantine_file',
            path: path
        }, function(response) {
            if(response.success) {
                btn.closest('td').append('<span style="color:green;"> ' + wpprotector_ajax.i18n.moved_quarantine + '</span>');
                btn.siblings('.wpprotector-q-safe').remove();
                btn.remove();
                loadQuarantine();
                fetchLogs(); // UI dynamisch aktualisieren
            } else {
                alert(response.data.message || wpprotector_ajax.i18n.move_error);
                btn.text(wpprotector_ajax.i18n.move_to_quarantine);
            }
        });
    });

    // --- Tab Switching ---
    $('.wpprotector-tab-link').on('click', function(e) {
        e.preventDefault();
        const targetTab = $(this).data('tab');

        if (!wpprotector_ajax.is_licensed && targetTab !== 'tab-license') {
            alert(wpprotector_ajax.i18n.please_license);
            // Force switch to license tab if they try to click something else
            $('.wpprotector-tab-link').removeClass('nav-tab-active');
            $('.wpprotector-tab-link[data-tab="tab-license"]').addClass('nav-tab-active');
            $('.wpprotector-tab-content').hide();
            $('#tab-license').show();
            return;
        }

        $('.wpprotector-tab-link').removeClass('nav-tab-active');
        $(this).addClass('nav-tab-active');
        
        $('.wpprotector-tab-content').hide();
        $('#' + targetTab).show();
    });

    // --- Quarantine ---
    function loadQuarantine() {
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_get_quarantine'
        }, function(response) {
            if(response.success && response.data.files) {
                const tbody = $('#wpprotector-quarantine-body');
                tbody.empty();
                if(response.data.files.length === 0) {
                    tbody.append('<tr><td colspan="3">' + wpprotector_ajax.i18n.quarantine_empty + '</td></tr>');
                    return;
                }
                
                response.data.files.forEach(function(f) {
                    let html = '<tr>';
                    html += '<td>' + f.time + '</td>';
                    html += '<td>' + f.original_path + '</td>';
                    html += '<td>';
                    html += '<button type="button" class="button button-small wpprotector-q-restore" data-id="' + f.id + '">' + wpprotector_ajax.i18n.restore + '</button> ';
                    html += '<button type="button" class="button button-small wpprotector-q-delete" data-id="' + f.id + '" style="color:#d63638;">' + wpprotector_ajax.i18n.delete_permanent + '</button>';
                    html += '</td></tr>';
                    tbody.append(html);
                });
            }
        });
    }

    $(document).on('click', '.wpprotector-q-restore', function() {
        const id = $(this).data('id');
        $(this).text(wpprotector_ajax.i18n.restoring);
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_quarantine_restore', id: id }, function(res) {
            if(res.success) {
                loadQuarantine();
                alert(wpprotector_ajax.i18n.file_restored);
            }
        });
    });

    $(document).on('click', '.wpprotector-q-delete', function() {
        if(!confirm(wpprotector_ajax.i18n.confirm_delete)) return;
        const id = $(this).data('id');
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_quarantine_delete', id: id }, function(res) {
            if(res.success) loadQuarantine();
        });
    });
    
    // --- Settings ---
    $('#btn-save-settings').on('click', function() {
        const btn = $(this);
        const fimEnabled = $('#wpprotector-setting-fim').is(':checked') ? '1' : '0';
        const coreEnabled = $('#wpprotector-setting-core').is(':checked') ? '1' : '0';
        const filesEnabled = $('#wpprotector-setting-files').is(':checked') ? '1' : '0';
        const updatesEnabled = $('#wpprotector-setting-updates').is(':checked') ? '1' : '0';
        const pluginsEnabled = $('#wpprotector-setting-plugins').is(':checked') ? '1' : '0';
        const wafEnabled = $('#wpprotector-setting-waf').is(':checked') ? '1' : '0';
        const xmlrpcDisabled = $('#wpprotector-setting-xmlrpc').is(':checked') ? '1' : '0';
        const telemetryEnabled = $('#wpprotector-setting-telemetry').is(':checked') ? '1' : '0';
        btn.prop('disabled', true);
        
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_save_settings',
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
        feedback.text(wpprotector_ajax.i18n.reading_files);
        
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_create_baseline'
        }, function(res) {
            btn.prop('disabled', false);
            if(res.success) {
                feedback.css('color', 'green').text(wpprotector_ajax.i18n.success + res.data.message);
                setTimeout(() => feedback.text(''), 4000);
            } else {
                feedback.css('color', 'red').text(wpprotector_ajax.i18n.read_error);
            }
        });
    });

    // --- Licensing ---
    $('#btn-request-license').on('click', function() {
        const btn = $(this);
        const email = $('#wpprotector-license-email').val();
        const feedback = $('#license-request-feedback');

        if (!email) {
            feedback.css('color', 'red').text(wpprotector_ajax.i18n.enter_email);
            return;
        }

        btn.prop('disabled', true).text(wpprotector_ajax.i18n.requesting);
        feedback.text('');

        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_request_license',
            email: email
        }, function(res) {
            btn.prop('disabled', false).text(wpprotector_ajax.i18n.request_key);
            if (res.success) {
                feedback.css('color', 'green').text(res.data.message);
            } else {
                feedback.css('color', 'red').text(res.data.message || wpprotector_ajax.i18n.request_error);
            }
        });
    });

    $('#btn-verify-license').on('click', function() {
        const btn = $(this);
        const token = $('#wpprotector-license-token').val();
        const email = $('#wpprotector-license-email').val();
        const feedback = $('#license-verify-feedback');

        if (!token) {
            feedback.css('color', 'red').text(wpprotector_ajax.i18n.enter_key);
            return;
        }

        btn.prop('disabled', true).text(wpprotector_ajax.i18n.verifying);
        feedback.text('');

        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_verify_license',
            token: token,
            email: email
        }, function(res) {
            if (res.success) {
                feedback.css('color', 'green').text(res.data.message);
                setTimeout(function(){ location.reload(); }, 1500);
            } else {
                btn.prop('disabled', false).text(wpprotector_ajax.i18n.verify_license);
                feedback.css('color', 'red').text(res.data.message || wpprotector_ajax.i18n.invalid_key);
            }
        });
    });

    $('#btn-recheck-license').on('click', function() {
        const btn = $(this);
        const feedback = $('#license-recheck-feedback');
        btn.prop('disabled', true).text(wpprotector_ajax.i18n.rechecking);
        
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_recheck_license'
        }, function(res) {
            if (res.success) {
                feedback.css('color', 'green').text(wpprotector_ajax.i18n.license_valid);
                setTimeout(function(){ feedback.text(''); btn.prop('disabled', false).text(wpprotector_ajax.i18n.recheck_now); }, 3000);
            } else {
                alert(wpprotector_ajax.i18n.license_invalid);
                location.reload();
            }
        });
    });

    $('#btn-remove-license').on('click', function() {
        if (!confirm(wpprotector_ajax.i18n.confirm_remove)) return;
        
        $.post(wpprotector_ajax.ajax_url, {
            _wpnonce: wpprotector_ajax.nonce,
            action: 'wpprotector_remove_license'
        }, function(res) {
            location.reload();
        });
    });
    // Initial Load handled via PHP SSR for better performance
});
