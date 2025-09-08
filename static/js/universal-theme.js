/**
 * Universal Cyberpunk Theme JavaScript
 * Applied to All Pages for Consistent Functionality
 */

// Global theme variables
const CyberpunkTheme = {
    particles: [],
    animationId: null,
    isInitialized: false
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initUniversalTheme();
});

/**
 * Initialize universal theme functionality
 */
function initUniversalTheme() {
    if (CyberpunkTheme.isInitialized) return;
    
    // Initialize core functionality
    initPasswordToggles();
    initFormEnhancements();
    initButtonAnimations();
    initCyberParticles();
    initScrollEffects();
    initTooltips();
    
    // Mark as initialized
    CyberpunkTheme.isInitialized = true;
    
    console.log('🔮 Cyberpunk Theme Initialized');
}

/**
 * Initialize password visibility toggles
 */
function initPasswordToggles() {
    const toggleButtons = document.querySelectorAll('.toggle-password, #togglePassword');
    
    toggleButtons.forEach(toggle => {
        const passwordInput = toggle.closest('.input-group')?.querySelector('input[type="password"], input[type="text"]') ||
                             document.getElementById('password');
        
        if (passwordInput) {
            toggle.addEventListener('click', function() {
                const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                passwordInput.setAttribute('type', type);
                
                // Toggle icon
                this.classList.toggle('fa-eye');
                this.classList.toggle('fa-eye-slash');
                
                // Add glow effect
                this.style.color = type === 'text' ? 'var(--accent-cyan)' : 'var(--text-muted)';
            });
        }
    });
}

/**
 * Initialize form enhancements
 */
function initFormEnhancements() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        // Add loading state to submit buttons
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"], input[type="submit"], .login-btn');
            
            if (submitBtn && !submitBtn.classList.contains('loading')) {
                submitBtn.classList.add('loading');
                
                // Store original content
                const originalContent = submitBtn.innerHTML;
                
                // Add loading spinner
                if (submitBtn.classList.contains('login-btn')) {
                    submitBtn.innerHTML = '<span>Authenticating</span><div class="spinner"></div>';
                } else {
                    submitBtn.innerHTML = '<span>Processing</span><div class="spinner"></div>';
                }
                
                // Reset after 5 seconds if form doesn't redirect
                setTimeout(() => {
                    if (submitBtn.classList.contains('loading')) {
                        submitBtn.classList.remove('loading');
                        submitBtn.innerHTML = originalContent;
                    }
                }, 5000);
            }
        });
        
        // Add focus effects to inputs
        const inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            input.addEventListener('focus', function() {
                this.parentElement?.classList.add('focused');
                addGlowEffect(this);
            });
            
            input.addEventListener('blur', function() {
                this.parentElement?.classList.remove('focused');
                removeGlowEffect(this);
            });
        });
    });
}

/**
 * Initialize button animations
 */
function initButtonAnimations() {
    const buttons = document.querySelectorAll('.btn, button, input[type="submit"]');
    
    buttons.forEach(button => {
        // Add ripple effect on click
        button.addEventListener('click', function(e) {
            createRippleEffect(e, this);
        });
        
        // Add hover glow enhancement
        button.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px) scale(1.02)';
        });
        
        button.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0) scale(1)';
        });
    });
}

/**
 * Create ripple effect on button click
 */
function createRippleEffect(event, element) {
    const ripple = document.createElement('span');
    const rect = element.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = event.clientX - rect.left - size / 2;
    const y = event.clientY - rect.top - size / 2;
    
    ripple.style.cssText = `
        position: absolute;
        width: ${size}px;
        height: ${size}px;
        left: ${x}px;
        top: ${y}px;
        background: rgba(76, 201, 240, 0.3);
        border-radius: 50%;
        transform: scale(0);
        animation: ripple 0.6s ease-out;
        pointer-events: none;
        z-index: 1;
    `;
    
    // Add ripple animation CSS if not exists
    if (!document.querySelector('#ripple-styles')) {
        const style = document.createElement('style');
        style.id = 'ripple-styles';
        style.textContent = `
            @keyframes ripple {
                to {
                    transform: scale(2);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }
    
    element.style.position = 'relative';
    element.style.overflow = 'hidden';
    element.appendChild(ripple);
    
    // Remove ripple after animation
    setTimeout(() => {
        ripple.remove();
    }, 600);
}

/**
 * Initialize cyber particles animation
 */
function initCyberParticles() {
    // Only add particles to login page or pages with special-page class
    if (!document.body.classList.contains('login-page') && 
        !document.body.classList.contains('special-page')) {
        return;
    }
    
    const container = document.querySelector('.login-container') || document.body;
    
    // Create particles
    function createParticle() {
        const particle = document.createElement('div');
        particle.classList.add('cyber-particle');
        
        // Random starting position
        particle.style.left = Math.random() * window.innerWidth + 'px';
        particle.style.animationDuration = (Math.random() * 3 + 3) + 's';
        particle.style.animationDelay = Math.random() * 2 + 's';
        
        container.appendChild(particle);
        
        // Remove particle after animation
        setTimeout(() => {
            if (particle.parentNode) {
                particle.remove();
            }
        }, 8000);
    }
    
    // Create initial particles
    for (let i = 0; i < 15; i++) {
        setTimeout(() => createParticle(), i * 200);
    }
    
    // Continue creating particles
    setInterval(createParticle, 800);
}

/**
 * Initialize scroll effects
 */
function initScrollEffects() {
    // Add scroll-based animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
            }
        });
    }, observerOptions);
    
    // Observe cards and sections
    const elements = document.querySelectorAll('.card, .panel, .section, .dashboard-card');
    elements.forEach(el => {
        observer.observe(el);
    });
}

/**
 * Initialize tooltips
 */
function initTooltips() {
    const elementsWithTooltips = document.querySelectorAll('[title], [data-tooltip]');
    
    elementsWithTooltips.forEach(element => {
        const tooltipText = element.getAttribute('title') || element.getAttribute('data-tooltip');
        
        if (tooltipText) {
            // Remove default title to prevent browser tooltip
            element.removeAttribute('title');
            
            element.addEventListener('mouseenter', function(e) {
                showTooltip(e, tooltipText);
            });
            
            element.addEventListener('mouseleave', function() {
                hideTooltip();
            });
        }
    });
}

/**
 * Show custom tooltip
 */
function showTooltip(event, text) {
    const tooltip = document.createElement('div');
    tooltip.id = 'cyber-tooltip';
    tooltip.textContent = text;
    tooltip.style.cssText = `
        position: absolute;
        background: var(--bg-card);
        color: var(--text-primary);
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 12px;
        border: 1px solid var(--accent-cyan);
        box-shadow: var(--glow-cyan);
        z-index: 10000;
        pointer-events: none;
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
    `;
    
    document.body.appendChild(tooltip);
    
    // Position tooltip
    const rect = event.target.getBoundingClientRect();
    tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
    tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';
}

/**
 * Hide custom tooltip
 */
function hideTooltip() {
    const tooltip = document.getElementById('cyber-tooltip');
    if (tooltip) {
        tooltip.remove();
    }
}

/**
 * Add glow effect to element
 */
function addGlowEffect(element) {
    element.style.boxShadow = '0 0 15px rgba(76, 201, 240, 0.3)';
    element.style.borderColor = 'var(--accent-cyan)';
}

/**
 * Remove glow effect from element
 */
function removeGlowEffect(element) {
    element.style.boxShadow = '';
    element.style.borderColor = '';
}

/**
 * Initialize status indicators with pulsing animation
 */
function initStatusIndicators() {
    const statusIndicators = document.querySelectorAll('.status-indicator');
    
    statusIndicators.forEach(indicator => {
        if (indicator.classList.contains('online') || indicator.classList.contains('processing')) {
            // Add pulsing animation
            indicator.style.animation = 'pulse 2s infinite';
        }
    });
}

/**
 * Initialize table enhancements
 */
function initTableEnhancements() {
    const tables = document.querySelectorAll('table');
    
    tables.forEach(table => {
        // Add hover effects to rows
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            row.addEventListener('mouseenter', function() {
                this.style.background = 'rgba(76, 201, 240, 0.05)';
                this.style.transform = 'scale(1.01)';
            });
            
            row.addEventListener('mouseleave', function() {
                this.style.background = '';
                this.style.transform = '';
            });
        });
    });
}

/**
 * Initialize navigation enhancements
 */
function initNavigationEnhancements() {
    const navLinks = document.querySelectorAll('.nav-link, .navbar-link, .card-links a');
    
    navLinks.forEach(link => {
        link.addEventListener('mouseenter', function() {
            this.style.transform = 'translateX(5px)';
            this.style.background = 'var(--bg-glass)';
            this.style.boxShadow = 'var(--glow-cyan)';
        });
        
        link.addEventListener('mouseleave', function() {
            this.style.transform = '';
            this.style.background = '';
            this.style.boxShadow = '';
        });
    });
}

/**
 * Initialize progress bar animations
 */
function initProgressBars() {
    const progressBars = document.querySelectorAll('.progress-bar');
    
    progressBars.forEach(bar => {
        const width = bar.style.width || bar.getAttribute('data-width') || '0%';
        bar.style.width = '0%';
        
        // Animate to target width
        setTimeout(() => {
            bar.style.width = width;
        }, 100);
    });
}

/**
 * Utility function to add cyberpunk glow to any element
 */
function addCyberpunkGlow(element, color = 'cyan') {
    const glowColors = {
        cyan: 'var(--glow-cyan)',
        purple: 'var(--glow-purple)',
        green: 'var(--glow-green)',
        red: 'var(--glow-red)'
    };
    
    element.style.boxShadow = glowColors[color] || glowColors.cyan;
}

/**
 * Utility function to create notification
 */
function createNotification(message, type = 'info', duration = 5000) {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} fade-in`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'danger' ? 'exclamation-triangle' : 'info-circle'}"></i>
        ${message}
    `;
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        min-width: 300px;
        max-width: 500px;
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after duration
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 300);
    }, duration);
}

/**
 * Initialize all enhancements after theme is loaded
 */
function initAllEnhancements() {
    initStatusIndicators();
    initTableEnhancements();
    initNavigationEnhancements();
    initProgressBars();
}

// Initialize enhancements after a short delay to ensure DOM is ready
setTimeout(initAllEnhancements, 100);

// Export functions for global use
window.CyberpunkTheme = {
    ...CyberpunkTheme,
    addGlow: addCyberpunkGlow,
    notify: createNotification,
    createRipple: createRippleEffect
};

// Initialize theme on script load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initUniversalTheme);
} else {
    initUniversalTheme();
}