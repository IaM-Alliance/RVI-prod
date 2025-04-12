// Main JavaScript file for IaM-Alliance Vetting System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize any interactive elements
    initializePasswordToggle();
    initializeDataTables();
    initializeAlertDismiss();
    
    // Listen for theme changes
    listenForThemeChanges();
});

function initializePasswordToggle() {
    // Find all password toggle buttons
    const toggleButtons = document.querySelectorAll('.password-toggle');
    
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const passwordField = document.getElementById(targetId);
            
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                this.innerHTML = '<i class="fas fa-eye-slash"></i>';
            } else {
                passwordField.type = 'password';
                this.innerHTML = '<i class="fas fa-eye"></i>';
            }
        });
    });
}

function initializeDataTables() {
    // Initialize DataTables if the library is loaded and jQuery is available
    if (typeof jQuery !== 'undefined' && typeof jQuery.fn.DataTable !== 'undefined') {
        jQuery('.data-table').DataTable({
            responsive: true,
            order: [[0, 'desc']]
        });
    } else if (typeof jQuery === 'undefined') {
        console.warn('jQuery is not loaded, DataTables initialization skipped');
    } else if (typeof jQuery.fn.DataTable === 'undefined') {
        console.warn('DataTables library is not loaded, initialization skipped');
    }
}

function initializeAlertDismiss() {
    // Alerts are now persistent by default, only adding event listeners for manual dismissal
    const closeButtons = document.querySelectorAll('.alert .btn-close');
    
    closeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const alert = this.closest('.alert');
            alert.classList.add('fade');
            setTimeout(() => {
                alert.remove();
            }, 500);
        });
    });
}

function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}

// Function to copy text to clipboard
function copyToClipboard(text) {
    // Check if Clipboard API is available
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
            .then(() => {
                alert('Copied to clipboard!');
            })
            .catch(err => {
                console.error('Error copying text: ', err);
                fallbackCopyToClipboard(text);
            });
    } else {
        fallbackCopyToClipboard(text);
    }
}

// Fallback method for copying to clipboard using a temporary input element
function fallbackCopyToClipboard(text) {
    try {
        // Create a temporary input element
        const input = document.createElement('input');
        input.setAttribute('value', text);
        document.body.appendChild(input);
        
        // Select and copy the text
        input.select();
        document.execCommand('copy');
        
        // Remove the temporary element
        document.body.removeChild(input);
        
        // Show success message
        alert('Copied to clipboard!');
    } catch (err) {
        console.error('Fallback: Error copying text to clipboard', err);
        alert('Could not copy text: ' + text);
    }
}

// Listen for theme changes
function listenForThemeChanges() {
    // Use MutationObserver to watch for theme attribute changes
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.attributeName === 'data-bs-theme') {
                const theme = document.documentElement.getAttribute('data-bs-theme');
                updateUIForTheme(theme);
            }
        });
    });
    
    // Start observing the document with the configured parameters
    observer.observe(document.documentElement, { attributes: true });
    
    // Also check for theme select elements on the page (for the preferences page)
    const themeSelect = document.getElementById('theme');
    if (themeSelect) {
        themeSelect.addEventListener('change', function() {
            updateUIForTheme(this.value);
        });
    }
    
    // Initialize UI based on current theme
    const currentTheme = document.documentElement.getAttribute('data-bs-theme');
    updateUIForTheme(currentTheme);
}

// Update UI elements based on selected theme
function updateUIForTheme(theme) {
    const navbar = document.querySelector('.navbar');
    const footer = document.querySelector('footer');
    
    if (theme === 'light') {
        // Switch to light theme
        if (navbar) {
            navbar.classList.remove('navbar-dark', 'bg-dark');
            navbar.classList.add('navbar-light', 'bg-light');
        }
        
        if (footer) {
            footer.classList.remove('bg-dark');
            footer.classList.add('bg-light');
        }
    } else {
        // Switch to dark theme
        if (navbar) {
            navbar.classList.remove('navbar-light', 'bg-light');
            navbar.classList.add('navbar-dark', 'bg-dark');
        }
        
        if (footer) {
            footer.classList.remove('bg-light');
            footer.classList.add('bg-dark');
        }
    }
}
