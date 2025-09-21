// SkillSwap Frontend JavaScript
// Global utilities and common functions

// Authentication utilities
function isLoggedIn() {
    return localStorage.getItem('token') !== null;
}

function getCurrentUser() {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
}

function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
}

// API fetch with authentication
async function fetchWithAuth(url, options = {}) {
    const token = localStorage.getItem('token');
    return fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    });
}

// Logout function
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/';
}

// Show alerts
function showAlert(message, type = 'info', duration = 5000) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    
    // Insert at the top of the main container
    const container = document.querySelector('.container');
    if (container) {
        container.insertBefore(alertDiv, container.firstChild);
        
        // Auto-remove after duration
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.parentNode.removeChild(alertDiv);
            }
        }, duration);
    }
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

// Validate email
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Initialize page-specific functionality
document.addEventListener('DOMContentLoaded', function() {
    // Update navigation based on login status
    updateNavigation();
    
    // Add smooth scrolling to anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });
});

function updateNavigation() {
    const navLinks = document.getElementById('navLinks');
    if (!navLinks) return;
    
    if (isLoggedIn()) {
        const user = getCurrentUser();
        navLinks.innerHTML = `
            <li><a href="/dashboard">Dashboard</a></li>
            <li><a href="/skills">Browse Skills</a></li>
            <li><a href="/add-skill">Add Skill</a></li>
            <li><a href="#" onclick="logout()">Logout (${user ? user.username : 'User'})</a></li>
        `;
    } else {
        navLinks.innerHTML = `
            <li><a href="/">Home</a></li>
            <li><a href="/skills">Browse Skills</a></li>
            <li><a href="/login">Login</a></li>
            <li><a href="/register">Register</a></li>
        `;
    }
}

// Form validation helpers
function validateForm(formId, rules) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    let isValid = true;
    const errors = [];
    
    for (const fieldName in rules) {
        const field = form.querySelector(`[name="${fieldName}"]`);
        if (!field) continue;
        
        const value = field.value.trim();
        const rule = rules[fieldName];
        
        // Required validation
        if (rule.required && !value) {
            errors.push(`${rule.label || fieldName} is required`);
            isValid = false;
            continue;
        }
        
        // Minimum length validation
        if (rule.minLength && value.length < rule.minLength) {
            errors.push(`${rule.label || fieldName} must be at least ${rule.minLength} characters`);
            isValid = false;
        }
        
        // Email validation
        if (rule.email && value && !isValidEmail(value)) {
            errors.push(`${rule.label || fieldName} must be a valid email address`);
            isValid = false;
        }
        
        // Custom validation
        if (rule.custom && !rule.custom(value)) {
            errors.push(rule.customMessage || `${rule.label || fieldName} is invalid`);
            isValid = false;
        }
    }
    
    // Display errors
    if (!isValid) {
        showAlert(errors.join('\n'), 'error');
    }
    
    return isValid;
}

// Credit system helpers
function formatCredits(credits) {
    return `${credits} credit${credits !== 1 ? 's' : ''}`;
}

function creditsToTime(credits) {
    const minutes = credits * 15; // Assuming 1 credit = 15 minutes
    if (minutes < 60) {
        return `${minutes} minutes`;
    } else {
        const hours = Math.floor(minutes / 60);
        const remainingMinutes = minutes % 60;
        return remainingMinutes > 0 ? 
            `${hours}h ${remainingMinutes}m` : 
            `${hours} hour${hours !== 1 ? 's' : ''}`;
    }
}

// Loading states
function showLoading(elementId, message = 'Loading...') {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="text-center" style="padding: 2rem;">
                <div style="display: inline-block; animation: spin 1s linear infinite; font-size: 1.5rem;">⟳</div>
                <p style="margin-top: 1rem;">${message}</p>
            </div>
        `;
    }
}

// Add CSS for loading spinner
const style = document.createElement('style');
style.textContent = `
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
`;
document.head.appendChild(style);

// Error handling
function handleApiError(error, context = 'Operation') {
    console.error(`${context} failed:`, error);
    
    if (error.message && error.message.includes('401')) {
        showAlert('Your session has expired. Please log in again.', 'error');
        setTimeout(() => {
            logout();
        }, 2000);
    } else {
        showAlert(`${context} failed. Please try again.`, 'error');
    }
}

// Local storage helpers
function saveToStorage(key, data) {
    try {
        localStorage.setItem(key, JSON.stringify(data));
        return true;
    } catch (error) {
        console.error('Failed to save to localStorage:', error);
        return false;
    }
}

function loadFromStorage(key, defaultValue = null) {
    try {
        const data = localStorage.getItem(key);
        return data ? JSON.parse(data) : defaultValue;
    } catch (error) {
        console.error('Failed to load from localStorage:', error);
        return defaultValue;
    }
}

// Export for use in other scripts
window.SkillSwap = {
    isLoggedIn,
    getCurrentUser,
    getAuthHeaders,
    fetchWithAuth,
    logout,
    showAlert,
    formatDate,
    isValidEmail,
    validateForm,
    formatCredits,
    creditsToTime,
    showLoading,
    handleApiError,
    saveToStorage,
    loadFromStorage
};