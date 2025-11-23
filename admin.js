import { supabase } from './supabaseClient.js';
import { setupNavUser } from './navAuth.js';

// ==========================================
// Global State
// ==========================================
const state = {
  currentSection: 'dashboard',
  challenges: [],
  users: [],
  submissions: [],
  hints: [],
  selectedChallenge: null,
  currentUser: null
};

// ==========================================
// Admin Access Check (RUNS FIRST)
// ==========================================
async function checkAdminAccess() {
  try {
    // Step 1: Get current auth user
    const { data: authData, error: authError } = await supabase.auth.getUser();
    
    if (authError || !authData.user) {
      console.error('Auth error:', authError);
      alert('กรุณาเข้าสู่ระบบก่อน');
      window.location.href = '/login.html';
      return false;
    }

    const authUser = authData.user;
    console.log('Auth user:', authUser.email);

    // Step 2: Query users table by email (since user_id in auth is UUID)
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('user_id, username, email, display_name, role, score, avatar, status')
      .eq('email', authUser.email)
      .single();

    if (userError) {
      console.error('Database error:', userError);
      
      // User not found in users table
      if (userError.code === 'PGRST116') {
        alert('ผู้ใช้ไม่พบในระบบ กรุณาติดต่อผู้ดูแลระบบ');
        window.location.href = '/login.html';
        return false;
      }
      
      // Other database errors
      alert('เกิดข้อผิดพลาดในการตรวจสอบสิทธิ์: ' + userError.message);
      console.error('Full error:', userError);
      window.location.href = '/login.html';
      return false;
    }

    // Step 3: Check if user exists
    if (!userData) {
      alert('ผู้ใช้ไม่พบในระบบ');
      window.location.href = '/login.html';
      return false;
    }

    // Step 4: Check if user has admin role
    if (userData.role !== 'admin') {
      alert('❌ คุณไม่มีสิทธิ์เข้าถึงหน้านี้\n\nเฉพาะ Admin เท่านั้นที่สามารถเข้าถึงได้');
      console.warn('Access denied - User role:', userData.role, '(Admin only)');
      window.location.href = '/login.html';
      return false;
    }

    // Step 5: Check if user status is active
    if (userData.status !== 'active') {
      alert('❌ บัญชีของคุณไม่ได้ใช้งาน\n\nสถานะ: ' + userData.status);
      window.location.href = '/login.html';
      return false;
    }

    // Step 6: Admin access granted!
    console.log('✅ Admin access granted for:', userData.username);
    state.currentUser = userData;
    
    // Update UI with admin info
    const adminUsernameEl = document.getElementById('adminUsername');
    if (adminUsernameEl) {
      adminUsernameEl.textContent = `${userData.display_name || userData.username} (Admin)`;
    }

    return true;

  } catch (err) {
    console.error('Unexpected error in checkAdminAccess:', err);
    alert('เกิดข้อผิดพลาดที่ไม่คาดคิด: ' + err.message);
    window.location.href = '/login.html';
    return false;
  }
}

// ==========================================
// Page Initialization
// ==========================================
document.addEventListener('DOMContentLoaded', async () => {
  // Hide page content immediately
  const mainContent = document.querySelector('.admin-container') || document.body;
  mainContent.style.display = 'none';
  
  // Show loading spinner
  const loadingSpinner = document.getElementById('loadingSpinner');
  if (loadingSpinner) {
    loadingSpinner.style.display = 'flex';
  }

  console.log('🔐 Admin page loading - checking access...');
  const isAdmin = await checkAdminAccess();
  
  if (isAdmin) {
    console.log('✅ Admin verified - initializing admin dashboard');
    
    // Hide loading spinner
    if (loadingSpinner) {
      loadingSpinner.style.display = 'none';
    }
    
    // Show main content
    mainContent.style.display = 'block';
    
    initializeAdmin();
    setupEventListeners();
    loadDashboardData();
  } else {
    console.log('❌ Admin access denied');
    // User already redirected by checkAdminAccess()
  }
});

function initializeAdmin() {
  showSection('dashboard');
}

// ==========================================
// Navigation
// ==========================================
function showSection(sectionName) {
  state.currentSection = sectionName;

  document.querySelectorAll('.menu-item').forEach(item => item.classList.remove('active'));
  document.querySelector(`[onclick="showSection('${sectionName}')"]`)?.classList.add('active');

  document.querySelectorAll('.admin-section').forEach(sec => sec.classList.remove('active'));
  document.getElementById(`section-${sectionName}`)?.classList.add('active');

  loadSectionData(sectionName);
}

function loadSectionData(sectionName) {
  switch (sectionName) {
    case 'dashboard':
      loadDashboardData();
      break;
    case 'challenges':
      loadChallenges();
      break;
    case 'hints':
      loadHintsChallenges();
      break;
    case 'users':
      loadUsers();
      break;
    case 'submissions':
      loadSubmissions();
      break;
    case 'statistics':
      loadStatistics();
      break;
    case 'files':
      loadFiles();
      break;
  }
}

// ==========================================
// Event Listeners Setup
// ==========================================
function setupEventListeners() {
  document.getElementById('challengeForm')?.addEventListener('submit', handleChallengeSubmit);
  document.getElementById('hintForm')?.addEventListener('submit', handleHintSubmit);
  document.getElementById('fileUpload')?.addEventListener('change', handleFileUpload);
  document.getElementById('challengeImage')?.addEventListener('change', previewImage);

  const uploadArea = document.getElementById('uploadArea');
  if (uploadArea) {
    uploadArea.addEventListener('dragover', e => {
      e.preventDefault();
      uploadArea.style.borderColor = 'var(--primary)';
    });
    uploadArea.addEventListener('dragleave', () => {
      uploadArea.style.borderColor = 'var(--border)';
    });
    uploadArea.addEventListener('drop', e => {
      e.preventDefault();
      uploadArea.style.borderColor = 'var(--border)';
      handleFileUpload({ target: { files: e.dataTransfer.files } });
    });
  }
}

// ==========================================
// Dashboard
// ==========================================
async function loadDashboardData() {
  try {
    // Load challenge count
    const { count: challengeCount, error: challengeError } = await supabase
      .from('challenges')
      .select('*', { count: 'exact', head: true })
      .eq('is_active', true);

    // Load user count
    const { count: userCount, error: userError } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true })
      .eq('status', 'active');

    // Load submission count
    const { count: submissionCount, error: submissionError } = await supabase
      .from('submissions')
      .select('*', { count: 'exact', head: true });

    // Calculate solve rate
    const { data: correctSubmissions } = await supabase
      .from('submissions')
      .select('*', { count: 'exact', head: true })
      .eq('is_correct', true);

    const solveRate = submissionCount > 0 
      ? ((correctSubmissions?.length || 0) / submissionCount * 100).toFixed(1)
      : 0;

    // Update dashboard
    const totalChallengesEl = document.getElementById('totalChallenges');
    if (totalChallengesEl) totalChallengesEl.textContent = challengeCount || 0;

    const totalUsersEl = document.getElementById('totalUsers');
    if (totalUsersEl) totalUsersEl.textContent = userCount || 0;

    const totalSubmissionsEl = document.getElementById('totalSubmissions');
    if (totalSubmissionsEl) totalSubmissionsEl.textContent = submissionCount || 0;

    const solveRateEl = document.getElementById('solveRate');
    if (solveRateEl) solveRateEl.textContent = solveRate + '%';

    initializeCharts();
  } catch (error) {
    console.error('Error loading dashboard:', error);
  }
}

function initializeCharts() {
  // Chart.js initialization if needed
}

// ==========================================
// Challenges
// ==========================================
async function loadChallenges() {
  try {
    const { data: challenges, error } = await supabase
      .from('challenges')
      .select('challenge_id, code, title, category, difficulty, score_base, is_active, visibility')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Error loading challenges:', error);
      alert('ไม่สามารถโหลดข้อมูลแบบฝึกหัด');
      return;
    }

    state.challenges = challenges || [];
    renderChallengesTable();
  } catch (error) {
    console.error('Error loading challenges:', error);
  }
}

function renderChallengesTable() {
  const tbody = document.getElementById('challengesTableBody');
  if (!tbody) return;

  if (state.challenges.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center">ไม่มีแบบฝึกหัด</td></tr>';
    return;
  }

  tbody.innerHTML = state.challenges.map(ch => `
    <tr>
      <td><strong>${ch.code || '-'}</strong></td>
      <td>${ch.title}</td>
      <td><span class="badge badge-${ch.category}">${ch.category}</span></td>
      <td><span class="badge badge-${ch.difficulty}">${ch.difficulty}</span></td>
      <td>${ch.score_base || 0}</td>
      <td>${ch.visibility || '-'}</td>
      <td><span class="badge badge-${ch.is_active ? 'active' : 'inactive'}">${ch.is_active ? 'Active' : 'Inactive'}</span></td>
      <td>
        <button class="action-btn edit" onclick="editChallenge('${ch.challenge_id}')">Edit</button>
        <button class="action-btn delete" onclick="deleteChallenge('${ch.challenge_id}')">Delete</button>
      </td>
    </tr>
  `).join('');
}

function editChallenge(id) {
  console.log('Edit challenge:', id);
  // TODO: Implement challenge edit
}

async function deleteChallenge(id) {
  if (!confirm('คุณแน่ใจหรือว่าต้องการลบแบบฝึกหัดนี้?')) return;
  
  try {
    const { error } = await supabase
      .from('challenges')
      .delete()
      .eq('challenge_id', id);

    if (error) throw error;
    
    alert('ลบแบบฝึกหัดสำเร็จ');
    loadChallenges();
  } catch (error) {
    console.error('Error deleting challenge:', error);
    alert('ไม่สามารถลบแบบฝึกหัด');
  }
}

function handleChallengeSubmit(e) {
  e.preventDefault();
  // TODO: Implement challenge form submission
}

// ==========================================
// Users
// ==========================================
async function loadUsers() {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('user_id, username, email, display_name, role, score, status')
      .order('score', { ascending: false });

    if (error) {
      console.error('Error loading users:', error);
      alert('ไม่สามารถโหลดข้อมูลผู้ใช้');
      return;
    }

    state.users = users || [];
    renderUsersTable();
  } catch (error) {
    console.error('Error loading users:', error);
  }
}

function renderUsersTable() {
  const tbody = document.getElementById('usersTableBody');
  if (!tbody) return;

  if (state.users.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center">ไม่มีผู้ใช้</td></tr>';
    return;
  }

  tbody.innerHTML = state.users.map(u => `
    <tr>
      <td><strong>${u.username}</strong></td>
      <td>${u.email}</td>
      <td>${u.display_name || '-'}</td>
      <td><span class="badge badge-${u.role}">${u.role}</span></td>
      <td>${u.score || 0}</td>
      <td><span class="badge badge-${u.status === 'active' ? 'active' : 'inactive'}">${u.status}</span></td>
      <td>
        <button class="action-btn edit" onclick="changeUserRole('${u.user_id}')">Change Role</button>
        <button class="action-btn delete" onclick="deleteUser('${u.user_id}')">Delete</button>
      </td>
    </tr>
  `).join('');
}

function changeUserRole(userId) {
  const newRole = prompt('กรุณาใส่ Role ใหม่ (player/moderator/admin):');
  if (!newRole) return;

  if (!['player', 'moderator', 'admin'].includes(newRole)) {
    alert('Role ไม่ถูกต้อง');
    return;
  }

  updateUserRole(userId, newRole);
}

async function updateUserRole(userId, newRole) {
  try {
    const { error } = await supabase
      .from('users')
      .update({ role: newRole })
      .eq('user_id', userId);

    if (error) throw error;
    
    alert('อัปเดต Role สำเร็จ');
    loadUsers();
  } catch (error) {
    console.error('Error updating role:', error);
    alert('ไม่สามารถอัปเดต Role');
  }
}

async function deleteUser(userId) {
  if (!confirm('คุณแน่ใจหรือว่าต้องการลบผู้ใช้นี้?')) return;
  
  try {
    const { error } = await supabase
      .from('users')
      .delete()
      .eq('user_id', userId);

    if (error) throw error;
    
    alert('ลบผู้ใช้สำเร็จ');
    loadUsers();
  } catch (error) {
    console.error('Error deleting user:', error);
    alert('ไม่สามารถลบผู้ใช้');
  }
}

// ==========================================
// Hints
// ==========================================
async function loadHintsChallenges() {
  try {
    const { data: hints, error } = await supabase
      .from('hints')
      .select('hint_id, challenge_id, name, cost, order_index')
      .order('challenge_id', { ascending: true });

    if (error) throw error;
    
    state.hints = hints || [];
    renderHintsTable();
  } catch (error) {
    console.error('Error loading hints:', error);
  }
}

function renderHintsTable() {
  const tbody = document.getElementById('hintsTableBody');
  if (!tbody) return;

  if (state.hints.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center">ไม่มี Hints</td></tr>';
    return;
  }

  tbody.innerHTML = state.hints.map(h => `
    <tr>
      <td>${h.challenge_id}</td>
      <td>${h.name}</td>
      <td>${h.cost || 0}</td>
      <td>#${h.order_index}</td>
      <td>
        <button class="action-btn edit">Edit</button>
        <button class="action-btn delete">Delete</button>
      </td>
    </tr>
  `).join('');
}

function handleHintSubmit(e) {
  e.preventDefault();
  // TODO: Implement hint form submission
}

// ==========================================
// Submissions
// ==========================================
async function loadSubmissions() {
  try {
    const { data: submissions, error } = await supabase
      .from('submissions')
      .select('submission_id, user_id, challenge_id, is_correct, points, submitted_at')
      .order('submitted_at', { ascending: false })
      .limit(100);

    if (error) throw error;
    
    state.submissions = submissions || [];
    renderSubmissionsTable();
  } catch (error) {
    console.error('Error loading submissions:', error);
  }
}

function renderSubmissionsTable() {
  const tbody = document.getElementById('submissionsTableBody');
  if (!tbody) return;

  if (state.submissions.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center">ไม่มี Submissions</td></tr>';
    return;
  }

  tbody.innerHTML = state.submissions.map(s => `
    <tr>
      <td>${s.submission_id}</td>
      <td>${s.user_id}</td>
      <td>${s.challenge_id}</td>
      <td><span class="badge badge-${s.is_correct ? 'success' : 'error'}">${s.is_correct ? '✓ Correct' : '✗ Wrong'}</span></td>
      <td>${s.points || 0}</td>
      <td>${new Date(s.submitted_at).toLocaleString()}</td>
    </tr>
  `).join('');
}

// ==========================================
// Statistics
// ==========================================
async function loadStatistics() {
  try {
    // TODO: Load statistics data from database
    console.log('Loading statistics...');
  } catch (error) {
    console.error('Error loading statistics:', error);
  }
}

// ==========================================
// Files
// ==========================================
async function loadFiles() {
  try {
    // TODO: Load files from Supabase storage
    console.log('Loading files...');
  } catch (error) {
    console.error('Error loading files:', error);
  }
}

function handleFileUpload(e) {
  // TODO: Implement file upload
}

function previewImage(e) {
  // TODO: Implement image preview
}

// ==========================================
// Utility Functions
// ==========================================

// Logout function
async function logoutAdmin() {
  const { error } = await supabase.auth.signOut();
  if (!error) {
    window.location.href = '/login.html';
  }
}

// Make functions available globally
window.logoutAdmin = logoutAdmin;
window.showSection = showSection;
window.editChallenge = editChallenge;
window.deleteChallenge = deleteChallenge;
window.changeUserRole = changeUserRole;
window.deleteUser = deleteUser;