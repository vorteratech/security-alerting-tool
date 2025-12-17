/**
 * Security Alerting Tool - Settings Page JavaScript
 */

// Track selected providers and their configurations
const selectedProviders = {};
const configuredProviders = new Set();

// Provider field mappings
const providerFields = {
    // EDR
    'edr-sentinelone': {
        type: 'edr',
        provider: 'sentinelone',
        fields: {
            's1-url': { configKey: 'base_url', type: 'config' },
            's1-api-key': { configKey: 'api_key', type: 'secret' },
            's1-webhook-secret': { configKey: 'webhook_secret', type: 'secret' },
            's1-enabled': { configKey: 'enabled', type: 'checkbox' },
            's1-primary': { configKey: 'is_primary', type: 'checkbox' }
        }
    },
    'edr-crowdstrike': {
        type: 'edr',
        provider: 'crowdstrike',
        fields: {
            'cs-url': { configKey: 'base_url', type: 'config' },
            'cs-client-id': { configKey: 'client_id', type: 'config' },
            'cs-client-secret': { configKey: 'api_secret', type: 'secret' },
            'cs-webhook-secret': { configKey: 'webhook_secret', type: 'secret' },
            'cs-enabled': { configKey: 'enabled', type: 'checkbox' },
            'cs-primary': { configKey: 'is_primary', type: 'checkbox' }
        }
    },
    // PSA
    'psa-superops': {
        type: 'psa',
        provider: 'superops',
        fields: {
            'superops-subdomain': { configKey: 'subdomain', type: 'config' },
            'superops-api-key': { configKey: 'api_key', type: 'secret' },
            'superops-default-client': { configKey: 'default_client_id', type: 'config' },
            'superops-enabled': { configKey: 'enabled', type: 'checkbox' },
            'superops-primary': { configKey: 'is_primary', type: 'checkbox' }
        }
    },
    // Threat Intel
    'threat_intel-virustotal': {
        type: 'threat_intel',
        provider: 'virustotal',
        fields: {
            'vt-api-key': { configKey: 'api_key', type: 'secret' },
            'vt-enabled': { configKey: 'enabled', type: 'checkbox' }
        }
    },
    'threat_intel-alienvault': {
        type: 'threat_intel',
        provider: 'alienvault',
        fields: {
            'av-api-key': { configKey: 'api_key', type: 'secret' },
            'av-enabled': { configKey: 'enabled', type: 'checkbox' }
        }
    },
    // AI
    'ai-anthropic': {
        type: 'ai',
        provider: 'anthropic',
        fields: {
            'anthropic-api-key': { configKey: 'api_key', type: 'secret' },
            'anthropic-model': { configKey: 'model', type: 'config' },
            'anthropic-enabled': { configKey: 'enabled', type: 'checkbox' },
            'anthropic-primary': { configKey: 'is_primary', type: 'checkbox' }
        }
    },
    'ai-openai': {
        type: 'ai',
        provider: 'openai',
        fields: {
            'openai-api-key': { configKey: 'api_key', type: 'secret' },
            'openai-model': { configKey: 'model', type: 'config' },
            'openai-enabled': { configKey: 'enabled', type: 'checkbox' },
            'openai-primary': { configKey: 'is_primary', type: 'checkbox' }
        }
    },
    'ai-gemini': {
        type: 'ai',
        provider: 'gemini',
        fields: {
            'gemini-api-key': { configKey: 'api_key', type: 'secret' },
            'gemini-model': { configKey: 'model', type: 'config' },
            'gemini-enabled': { configKey: 'enabled', type: 'checkbox' },
            'gemini-primary': { configKey: 'is_primary', type: 'checkbox' }
        }
    },
    // Chat
    'chat-teams': {
        type: 'chat',
        provider: 'teams',
        fields: {
            'teams-webhook-url': { configKey: 'webhook_url', type: 'config' },
            'teams-bot-app-id': { configKey: 'bot_app_id', type: 'config' },
            'teams-bot-app-secret': { configKey: 'api_secret', type: 'secret' },
            'teams-enabled': { configKey: 'enabled', type: 'checkbox' },
            'teams-primary': { configKey: 'is_primary', type: 'checkbox' }
        }
    }
};

/**
 * Toggle section collapse/expand
 */
function toggleSection(sectionId) {
    const content = document.getElementById(`${sectionId}-content`);
    const toggle = document.getElementById(`${sectionId}-toggle`);

    if (content.classList.contains('collapsed')) {
        content.classList.remove('collapsed');
        toggle.classList.remove('collapsed');
    } else {
        content.classList.add('collapsed');
        toggle.classList.add('collapsed');
    }
}

/**
 * Select a provider within a section
 */
function selectProvider(type, provider) {
    const key = `${type}-${provider}`;

    // Hide all provider configs in this section
    document.querySelectorAll(`#${type}-section .provider-config`).forEach(el => {
        el.style.display = 'none';
    });

    // Deselect all buttons in this section
    document.querySelectorAll(`#${type}-section .provider-btn`).forEach(btn => {
        btn.classList.remove('selected');
    });

    // Show selected config and highlight button
    const configEl = document.getElementById(`${key}-config`);
    const btnEl = document.querySelector(`[data-provider="${provider}"][data-type="${type}"]`);

    if (configEl) {
        configEl.style.display = 'block';
    }
    if (btnEl) {
        btnEl.classList.add('selected');
    }

    selectedProviders[type] = provider;
}

/**
 * Show notification message
 */
function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type}`;

    // Auto-hide after 5 seconds
    setTimeout(() => {
        notification.className = 'notification';
    }, 5000);
}

/**
 * Get form data for a specific provider
 */
function getProviderData(providerKey) {
    const mapping = providerFields[providerKey];
    if (!mapping) return null;

    const data = {
        enabled: true,
        is_primary: false,
        config: {},
        api_key: null,
        api_secret: null
    };

    for (const [fieldId, fieldInfo] of Object.entries(mapping.fields)) {
        const el = document.getElementById(fieldId);
        if (!el) continue;

        let value;
        if (fieldInfo.type === 'checkbox') {
            value = el.checked;
        } else {
            value = el.value.trim();
        }

        if (fieldInfo.configKey === 'enabled') {
            data.enabled = value;
        } else if (fieldInfo.configKey === 'is_primary') {
            data.is_primary = value;
        } else if (fieldInfo.configKey === 'api_key') {
            if (value) data.api_key = value;
        } else if (fieldInfo.configKey === 'api_secret') {
            if (value) data.api_secret = value;
        } else if (fieldInfo.type === 'config' || fieldInfo.type === 'secret') {
            if (value) data.config[fieldInfo.configKey] = value;
        }
    }

    return data;
}

/**
 * Save a single provider configuration
 * Always sends the request - backend handles merging with existing data
 */
async function saveProvider(providerKey) {
    const mapping = providerFields[providerKey];
    if (!mapping) return { success: false, error: 'Unknown provider' };

    const data = getProviderData(providerKey);
    if (!data) return { success: false, error: 'Could not get form data' };

    // Debug logging
    console.log(`[Save] ${providerKey}:`, JSON.stringify(data, null, 2));

    try {
        const response = await fetch(`/api/settings/${mapping.type}/${mapping.provider}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to save');
        }

        const result = await response.json();
        return { success: true, data: result };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Save all configured providers
 */
async function saveAllSettings() {
    const saveBtn = document.querySelector('.save-btn');
    const originalText = saveBtn.textContent;
    saveBtn.disabled = true;
    saveBtn.innerHTML = 'Saving... <span class="loading"></span>';

    const results = [];
    const errors = [];

    // Save all providers that have visible config panels
    for (const [key, mapping] of Object.entries(providerFields)) {
        const configEl = document.getElementById(`${key}-config`);
        if (!configEl || configEl.style.display === 'none') continue;

        const result = await saveProvider(key);
        if (result.success) {
            results.push(`${mapping.provider}`);
            markProviderConfigured(mapping.type, mapping.provider);
        } else {
            errors.push(`${mapping.provider}: ${result.error}`);
        }
    }

    saveBtn.disabled = false;
    saveBtn.textContent = originalText;

    if (errors.length > 0) {
        showNotification(`Errors saving: ${errors.join(', ')}`, 'error');
    } else if (results.length > 0) {
        showNotification(`Successfully saved: ${results.join(', ')}`, 'success');
    } else {
        showNotification('No providers selected. Click a provider button to configure it.', 'warning');
    }
}

/**
 * Mark a provider button as configured
 */
function markProviderConfigured(type, provider) {
    const btn = document.querySelector(`[data-provider="${provider}"][data-type="${type}"]`);
    if (btn) {
        btn.classList.add('configured');
    }
    configuredProviders.add(`${type}-${provider}`);
}

/**
 * Show the test modal
 */
function showTestModal() {
    const modal = document.getElementById('test-modal');
    const progress = document.getElementById('test-progress');
    const results = document.getElementById('test-results');
    const footer = document.getElementById('modal-footer');
    const title = document.getElementById('modal-title');

    title.textContent = 'Testing Connections';
    progress.style.display = 'flex';
    results.style.display = 'none';
    results.innerHTML = '';
    footer.style.display = 'none';
    modal.style.display = 'flex';
}

/**
 * Close the test modal
 */
function closeTestModal() {
    const modal = document.getElementById('test-modal');
    modal.style.display = 'none';
}

/**
 * Add a result to the modal
 */
function addTestResult(provider, success, message, details) {
    const results = document.getElementById('test-results');
    const icon = success ? '✓' : '✗';
    const statusClass = success ? 'success' : 'error';

    let detailsHtml = '';
    if (details && Object.keys(details).length > 0) {
        const detailsText = Object.entries(details)
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n');
        detailsHtml = `<div class="test-result-details">${detailsText}</div>`;
    }

    results.innerHTML += `
        <div class="test-result-item ${statusClass}">
            <span class="test-result-icon">${icon}</span>
            <div class="test-result-content">
                <div class="test-result-provider">${provider}</div>
                <div class="test-result-message">${message}</div>
                ${detailsHtml}
            </div>
        </div>
    `;
}

/**
 * Show test summary and OK button
 */
function showTestSummary(passed, failed) {
    const progress = document.getElementById('test-progress');
    const results = document.getElementById('test-results');
    const footer = document.getElementById('modal-footer');
    const title = document.getElementById('modal-title');

    progress.style.display = 'none';
    results.style.display = 'flex';
    footer.style.display = 'flex';

    let summaryClass = 'all-passed';
    let summaryText = `All ${passed} tests passed!`;

    if (failed > 0 && passed > 0) {
        summaryClass = 'some-failed';
        summaryText = `${passed} passed, ${failed} failed`;
    } else if (failed > 0 && passed === 0) {
        summaryClass = 'all-failed';
        summaryText = `All ${failed} tests failed`;
    }

    title.textContent = 'Test Results';
    results.innerHTML += `<div class="test-summary ${summaryClass}">${summaryText}</div>`;
}

/**
 * Test all configured integrations
 */
async function testConnections() {
    if (configuredProviders.size === 0) {
        showNotification('No integrations configured to test. Save settings first.', 'warning');
        return;
    }

    // Show modal with progress
    showTestModal();

    const testBtn = document.querySelector('.test-btn');
    testBtn.disabled = true;

    let passed = 0;
    let failed = 0;

    // Test each provider and show results as they come in
    for (const providerKey of configuredProviders) {
        const mapping = providerFields[providerKey];
        if (!mapping) continue;

        try {
            const response = await fetch(`/api/settings/${mapping.type}/${mapping.provider}/test`, {
                method: 'POST'
            });

            const result = await response.json();
            addTestResult(
                mapping.provider.charAt(0).toUpperCase() + mapping.provider.slice(1),
                result.success,
                result.message,
                result.details
            );

            if (result.success) {
                passed++;
            } else {
                failed++;
            }
        } catch (error) {
            addTestResult(
                mapping.provider.charAt(0).toUpperCase() + mapping.provider.slice(1),
                false,
                error.message,
                null
            );
            failed++;
        }
    }

    // Show summary and enable OK button
    showTestSummary(passed, failed);
    testBtn.disabled = false;
}

/**
 * Load existing settings on page load
 */
async function loadExistingSettings() {
    try {
        const response = await fetch('/api/settings');
        if (!response.ok) return;

        const data = await response.json();

        for (const integration of data.integrations) {
            const key = `${integration.integration_type}-${integration.provider}`;
            const mapping = providerFields[key];
            if (!mapping) continue;

            // Mark as configured
            markProviderConfigured(integration.integration_type, integration.provider);

            // Populate form fields
            for (const [fieldId, fieldInfo] of Object.entries(mapping.fields)) {
                const el = document.getElementById(fieldId);
                if (!el) continue;

                if (fieldInfo.configKey === 'enabled') {
                    el.checked = integration.enabled;
                } else if (fieldInfo.configKey === 'is_primary') {
                    el.checked = integration.is_primary;
                } else if (fieldInfo.type === 'config') {
                    const value = integration.config[fieldInfo.configKey];
                    if (value) el.value = value;
                }
                // Note: We don't populate secrets (api_key, api_secret) for security
            }

            // Show placeholder for secrets if they exist
            if (integration.has_api_key) {
                const keyFields = Object.entries(mapping.fields)
                    .filter(([_, info]) => info.configKey === 'api_key');
                for (const [fieldId, _] of keyFields) {
                    const el = document.getElementById(fieldId);
                    if (el) el.placeholder = '••••••••••••••••';
                }
            }
        }
    } catch (error) {
        console.error('Failed to load settings:', error);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadExistingSettings();
});
