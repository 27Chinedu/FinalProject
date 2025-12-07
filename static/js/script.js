// static/js/script.js

// Utility functions
const utils = {
    // Show loading spinner
    showLoading: (element) => {
        if (element) {
            element.disabled = true;
            element.innerHTML = '<span class="spinner"></span>';
        }
    },

    // Hide loading spinner
    hideLoading: (element, originalText) => {
        if (element) {
            element.disabled = false;
            element.innerHTML = originalText;
        }
    },

    // Format date
    formatDate: (dateString) => {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    },

    // Validate email
    isValidEmail: (email) => {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    },

    // Validate password strength
    isStrongPassword: (password) => {
        return password.length >= 8 &&
               /[A-Z]/.test(password) &&
               /[a-z]/.test(password) &&
               /[0-9]/.test(password) &&
               /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password);
    },

    // Check if user is authenticated
    isAuthenticated: () => {
        const token = localStorage.getItem('access_token');
        return !!token;
    },

    // Get auth headers
    getAuthHeaders: () => {
        const token = localStorage.getItem('access_token');
        return {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        };
    },

    // Logout user
    logout: () => {
        localStorage.clear();
        window.location.href = '/login';
    },

    // Handle API errors
    handleApiError: (error) => {
        if (error.status === 401) {
            utils.logout();
        }
        return error;
    }
};

// Export utils for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = utils;
}

console.log('Application scripts loaded successfully');