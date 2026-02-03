// Utility for fetching observable types from the FastAPI endpoint
// and populating <select> elements with them.

var _observableTypesCache = null;

/**
 * Fetch observable types from the API.
 * Caches the result in a module-level variable for the page lifetime.
 * @returns {Promise<string[]>} Array of observable type name strings.
 */
async function fetchObservableTypes() {
    if (_observableTypesCache !== null) {
        return _observableTypesCache;
    }

    var apiBase = window.ACE_API_V2_BASE || '/api/v2';
    var response = await fetch(apiBase + '/observable-types/', {
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json' }
    });

    if (!response.ok) {
        console.error('Failed to fetch observable types:', response.status);
        return [];
    }

    var result = await response.json();
    _observableTypesCache = result.data.map(function(item) { return item.name; });
    return _observableTypesCache;
}

/**
 * Populate a <select> element with observable type options from the API.
 *
 * @param {HTMLElement|string} selectElement - The <select> element or its ID/selector.
 * @param {Object} [options] - Configuration options.
 * @param {string} [options.defaultValue] - Pre-select this value.
 * @param {boolean} [options.includeBlank] - Prepend a blank placeholder option.
 * @param {string} [options.blankLabel] - Label for the blank option (default: "Select Type").
 * @param {boolean} [options.includeAny] - Prepend an "Any" option.
 */
async function populateObservableTypeSelect(selectElement, options) {
    options = options || {};

    // Resolve the element if a string selector/ID was passed
    if (typeof selectElement === 'string') {
        selectElement = document.querySelector(selectElement) || document.getElementById(selectElement);
    }

    if (!selectElement) {
        console.error('populateObservableTypeSelect: select element not found');
        return;
    }

    var types = await fetchObservableTypes();

    // Clear existing options
    selectElement.innerHTML = '';

    // Prepend blank placeholder if requested
    if (options.includeBlank) {
        var blankOpt = document.createElement('option');
        blankOpt.value = '';
        blankOpt.textContent = options.blankLabel || 'Select Type';
        blankOpt.selected = true;
        selectElement.appendChild(blankOpt);
    }

    // Prepend "Any" option if requested
    if (options.includeAny) {
        var anyOpt = document.createElement('option');
        anyOpt.value = 'Any';
        anyOpt.textContent = 'Any';
        selectElement.appendChild(anyOpt);
    }

    // Add each observable type
    for (var i = 0; i < types.length; i++) {
        var opt = document.createElement('option');
        opt.value = types[i];
        opt.textContent = types[i];
        if (options.defaultValue && types[i] === options.defaultValue) {
            opt.selected = true;
        }
        selectElement.appendChild(opt);
    }

    // If defaultValue is set but wasn't matched above (e.g. "Any"), select it
    if (options.defaultValue) {
        selectElement.value = options.defaultValue;
    }
}
