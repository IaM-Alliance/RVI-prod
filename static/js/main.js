// Main JavaScript file for IaM-Alliance Vetting System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize any interactive elements
    initializePasswordToggle();
    initializeDataTables();
    initializeAlertDismiss();
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
    // Initialize DataTables if the library is loaded
    if (typeof $.fn.DataTable !== 'undefined') {
        $('.data-table').DataTable({
            responsive: true,
            order: [[0, 'desc']]
        });
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
    navigator.clipboard.writeText(text)
        .then(() => {
            alert('Copied to clipboard!');
        })
        .catch(err => {
            console.error('Error copying text: ', err);
        });
}
