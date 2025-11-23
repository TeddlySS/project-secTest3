// register.js
import { supabase } from './supabaseClient.js';
import { getOAuthRedirect } from './config.js';

// ---------- UI: particles ----------
function createParticles() {
  const particlesContainer = document.getElementById('particles');
  if (!particlesContainer) return;

  for (let i = 0; i < 50; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * 100 + '%';
    particle.style.animationDelay = Math.random() * 15 + 's';
    particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
    particlesContainer.appendChild(particle);
  }
}

// ---------- UI: toggle password ----------
function togglePasswordVisibility(inputId, buttonId) {
  const input = document.getElementById(inputId);
  const button = document.getElementById(buttonId);

  if (!input || !button) return;

  button.addEventListener('click', () => {
    const type = input.type === 'password' ? 'text' : 'password';
    input.type = type;
    button.classList.toggle('visible', type === 'text');
  });
}

// ---------- UI: password strength & match ----------
function checkPasswordStrength(password) {
  const strengthBar = document.getElementById('passwordStrengthBar');
  const strengthText = document.getElementById('passwordStrengthText');
  if (!strengthBar || !strengthText) return;

  let score = 0;
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  strengthBar.style.width = (score * 25) + '%';

  const strengthLevels = ['Very weak', 'Weak', 'Medium', 'Strong', 'Very strong'];
  strengthText.textContent = strengthLevels[score] || 'Very weak';
}

function checkPasswordMatch() {
  const passwordInput = document.getElementById('password');
  const confirmInput = document.getElementById('confirmPassword');
  const matchIndicator = document.getElementById('passwordMatch');

  if (!passwordInput || !confirmInput || !matchIndicator) return;

  if (!confirmInput.value) {
    matchIndicator.textContent = '';
    matchIndicator.className = 'password-match';
    return;
  }

  if (passwordInput.value === confirmInput.value) {
    matchIndicator.textContent = 'Password matched';
    matchIndicator.className = 'password-match success';
  } else {
    matchIndicator.textContent = 'Password does not match';
    matchIndicator.className = 'password-match error';
  }
}

function validateForm() {
  const usernameInput = document.getElementById('username');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const confirmPasswordInput = document.getElementById('confirmPassword');
  const termsCheckbox = document.getElementById('terms');
  const registerBtn = document.getElementById('registerBtn');

  if (
    !usernameInput ||
    !emailInput ||
    !passwordInput ||
    !confirmPasswordInput ||
    !termsCheckbox ||
    !registerBtn
  ) return;

  const isValid =
    usernameInput.value.trim().length >= 3 &&
    emailInput.validity.valid &&
    passwordInput.value.trim().length >= 8 &&
    passwordInput.value === confirmPasswordInput.value &&
    termsCheckbox.checked;

  registerBtn.disabled = !isValid;
}

// ---------- helper ----------
function showMessage(msg) {
  alert(msg);
}

function validatePassword(password, confirmPassword) {
  if (password.length < 8) {
    return 'รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร';
  }
  if (password !== confirmPassword) {
    return 'รหัสผ่านและยืนยันรหัสผ่านต้องตรงกัน';
  }
  return null;
}

// ---------- ตรวจสอบว่า email / username ซ้ำใน table users หรือไม่ ----------
async function checkDuplicateEmailUsername(email, username) {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('email, username')
      .or(`email.eq.${email},username.eq.${username}`)
      .limit(1);

    if (error) {
      console.error('Check duplicate error:', error);
      return {
        ok: false,
        message: 'ไม่สามารถตรวจสอบ email / username ได้ กรุณาลองใหม่อีกครั้ง',
      };
    }

    if (!data || data.length === 0) {
      return { ok: true };
    }

    const existing = data[0];

    if (existing.email === email && existing.username === username) {
      return { ok: false, message: 'อีเมลและชื่อผู้ใช้นี้ถูกใช้แล้วในระบบ' };
    }
    if (existing.email === email) {
      return { ok: false, message: 'อีเมลนี้ถูกใช้สมัครไปแล้ว' };
    }
    if (existing.username === username) {
      return { ok: false, message: 'ชื่อผู้ใช้นี้ถูกใช้แล้ว กรุณาเลือกชื่ออื่น' };
    }

    return { ok: false, message: 'ข้อมูลซ้ำในระบบแล้ว' };
  } catch (err) {
    console.error('Unexpected duplicate check error:', err);
    return {
      ok: false,
      message: 'เกิดข้อผิดพลาดในการตรวจสอบข้อมูลซ้ำ กรุณาลองใหม่',
    };
  }
}

// ---------- สมัครสมาชิกด้วย Supabase ----------
async function handleRegistration(e) {
  e.preventDefault();

  const usernameInput = document.getElementById('username');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const confirmPasswordInput = document.getElementById('confirmPassword');
  const registerBtn = document.getElementById('registerBtn');

  if (
    !usernameInput ||
    !emailInput ||
    !passwordInput ||
    !confirmPasswordInput ||
    !registerBtn
  ) {
    showMessage('ฟอร์มไม่สมบูรณ์');
    return;
  }

  const username = usernameInput.value.trim();
  const email = emailInput.value.trim();
  const password = passwordInput.value.trim();
  const confirmPassword = confirmPasswordInput.value.trim();

  if (!username || !email || !password || !confirmPassword) {
    showMessage('กรุณากรอกข้อมูลให้ครบ');
    return;
  }

  const pwdError = validatePassword(password, confirmPassword);
  if (pwdError) {
    showMessage(pwdError);
    return;
  }

  registerBtn.disabled = true;
  const originalText = registerBtn.textContent;
  registerBtn.textContent = 'กำลังสร้างบัญชี...';

  try {
    // 1) เช็คในตาราง users ก่อนว่า email / username ซ้ำไหม
    const dup = await checkDuplicateEmailUsername(email, username);
    if (!dup.ok) {
      showMessage(dup.message);
      return;
    }

    // 2) สมัครใน Supabase Auth
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { username },
      },
    });

    if (error) {
      console.error('signUp error:', error);
      if (
        error.message &&
        error.message.toLowerCase().includes('user already registered')
      ) {
        showMessage('อีเมลนี้มีบัญชีในระบบแล้ว ลองเข้าสู่ระบบแทน');
      } else {
        showMessage(error.message || 'สมัครสมาชิกไม่สำเร็จ');
      }
      return;
    }

    // 3) บันทึกข้อมูลผู้เล่นลงตาราง users
    const { error: insertError } = await supabase.from('users').insert({
      username,
      email,
      display_name: username,
      score: 0,
      role: 'player',
      status: 'active',
    });

    if (insertError) {
      console.error('Insert users error:', insertError);
      showMessage(
        'สมัครสำเร็จบางส่วน แต่บันทึกข้อมูลผู้เล่นไม่สำเร็จ: ' +
          (insertError.message || '')
      );
      window.location.href = 'login.html';
      return;
    }

    // 4) สำเร็จ
    showMessage('สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ');
    window.location.href = 'login.html';
  } catch (err) {
    console.error('Registration error:', err);
    showMessage(err.message || 'เกิดข้อผิดพลาดระหว่างสมัครสมาชิก');
  } finally {
    registerBtn.disabled = false;
    registerBtn.textContent = originalText;
  }
}

// ---------- Google OAuth ในหน้า Register ----------
async function signInWithGoogleFromRegister() {
  try {
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: getOAuthRedirect(),
      },
    });

    if (error) {
      console.error(error);
      showMessage('ไม่สามารถเชื่อมต่อ Google ได้: ' + (error.message || 'unknown error'));
    }
  } catch (err) {
    console.error(err);
    showMessage('เกิดข้อผิดพลาดในการเชื่อมต่อ Google');
  }
}

window.handleGoogleSignIn = function () {
  signInWithGoogleFromRegister();
};

// ---------- Ready ----------
document.addEventListener('DOMContentLoaded', () => {
  createParticles();

  togglePasswordVisibility('password', 'togglePassword');
  togglePasswordVisibility('confirmPassword', 'toggleConfirmPassword');

  const passwordInput = document.getElementById('password');
  const confirmPasswordInput = document.getElementById('confirmPassword');
  const usernameInput = document.getElementById('username');
  const emailInput = document.getElementById('email');
  const termsCheckbox = document.getElementById('terms');
  const registerForm = document.getElementById('registerForm');

  if (passwordInput) {
    passwordInput.addEventListener('input', () => {
      checkPasswordStrength(passwordInput.value);
      checkPasswordMatch();
      validateForm();
    });
  }

  if (confirmPasswordInput) {
    confirmPasswordInput.addEventListener('input', () => {
      checkPasswordMatch();
      validateForm();
    });
  }

  if (usernameInput) {
    usernameInput.addEventListener('input', validateForm);
  }

  if (emailInput) {
    emailInput.addEventListener('input', validateForm);
  }

  if (termsCheckbox) {
    termsCheckbox.addEventListener('change', validateForm);
  }

  if (registerForm) {
    registerForm.addEventListener('submit', handleRegistration);
  }

  const firstInput = document.querySelector('.form-input');
  if (firstInput) {
    setTimeout(() => firstInput.focus(), 500);
  }

  validateForm();
});