const SUPABASE_URL = 'https://npfvvegmxgkkhyxkephc.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5wZnZ2ZWdteGdra2h5eGtlcGhjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzczODQzNzQsImV4cCI6MjA5Mjk2MDM3NH0.S4wKfp_5b_KJKyt4_yobbPZY6VVdyoaIHmGJXQs2FgU';

const loginForm = document.getElementById('login-form');
const btnLogin = document.getElementById('btn-login');
const alertBox = document.getElementById('alert-box');

function showAlert(message) {
    alertBox.textContent = message;
    alertBox.style.display = 'block';
}

if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        
        try {
            btnLogin.disabled = true;
            btnLogin.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...';
            alertBox.style.display = 'none';
            
            // Search for officer with matching email and password
            const response = await fetch(`${SUPABASE_URL}/rest/v1/police_officers?email=eq.${encodeURIComponent(email)}&password=eq.${encodeURIComponent(password)}`, {
                headers: {
                    'apikey': SUPABASE_KEY,
                    'Authorization': `Bearer ${SUPABASE_KEY}`
                }
            });
            
            const data = await response.json();
            
            if (!response.ok) throw new Error('Network error or server unavailable.');
            
            if (data.length === 1) {
                // Login Success
                localStorage.setItem('policeUser', JSON.stringify(data[0]));
                window.location.href = 'index.html';
            } else {
                // Login Failed
                throw new Error('Invalid Email or Password');
            }
            
        } catch (error) {
            console.error('Login error:', error);
            showAlert(error.message);
        } finally {
            btnLogin.disabled = false;
            btnLogin.innerHTML = '<i class="fa-solid fa-right-to-bracket"></i> Login';
        }
    });
}
