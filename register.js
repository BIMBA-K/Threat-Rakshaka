const SUPABASE_URL = 'https://npfvvegmxgkkhyxkephc.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5wZnZ2ZWdteGdra2h5eGtlcGhjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzczODQzNzQsImV4cCI6MjA5Mjk2MDM3NH0.S4wKfp_5b_KJKyt4_yobbPZY6VVdyoaIHmGJXQs2FgU';

const registerForm = document.getElementById('register-form');
const btnRegister = document.getElementById('btn-register');
const alertBox = document.getElementById('alert-box');

function showAlert(message, type = 'error') {
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type}`;
    alertBox.style.display = 'block';
}

if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const fullName = document.getElementById('reg-name').value;
        const badgeNumber = document.getElementById('reg-badge').value;
        const email = document.getElementById('reg-email').value;
        const password = document.getElementById('reg-password').value;
        
        try {
            btnRegister.disabled = true;
            btnRegister.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing...';
            alertBox.style.display = 'none';
            
            // Check if email or badge already exists (Manual check due to REST constraints if needed, but unique constraint in DB handles it)
            const response = await fetch(`${SUPABASE_URL}/rest/v1/police_officers`, {
                method: 'POST',
                headers: {
                    'apikey': SUPABASE_KEY,
                    'Authorization': `Bearer ${SUPABASE_KEY}`,
                    'Content-Type': 'application/json',
                    'Prefer': 'return=representation'
                },
                body: JSON.stringify({
                    full_name: fullName,
                    badge_number: badgeNumber,
                    email: email,
                    password: password
                })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                if (data.message && data.message.includes('unique')) {
                    throw new Error('Email or Badge Number already registered.');
                }
                throw new Error(data.message || 'Registration failed. Check network or table schema.');
            }
            
            showAlert('Registration Successful! Redirecting to login...', 'success');
            
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 2000);
            
        } catch (error) {
            console.error('Registration error:', error);
            showAlert(error.message);
        } finally {
            btnRegister.disabled = false;
            btnRegister.innerHTML = '<i class="fa-solid fa-user-check"></i> Register Account';
        }
    });
}
