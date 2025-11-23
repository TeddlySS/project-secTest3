// leaderboard.js (เวอร์ชันแก้ใหม่)
import { supabase } from './supabaseClient.js';
import { setupNavUser } from './navAuth.js';

let currentUserData = null;
let leaderboardData = [];

// ============================
// UI: particles
// ============================
function createParticles() {
  const particlesContainer = document.getElementById('particles');
  if (!particlesContainer) return;

  for (let i = 0; i < 100; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * 100 + '%';
    particle.style.animationDelay = Math.random() * 15 + 's';
    particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
    particlesContainer.appendChild(particle);
  }
}

// ============================
// Helpers
// ============================
async function getCurrentUserProfile() {
  try {
    const { data, error } = await supabase.auth.getSession();
    if (error) {
      console.error('getSession error:', error);
      return null;
    }
    if (!data.session) return null;

    const email = data.session.user.email;
    const { data: profile, error: profileError } = await supabase
      .from('users')
      .select('user_id, username, display_name, score, avatar')
      .eq('email', email)
      .single();

    if (profileError) {
      console.error('getCurrentUserProfile error:', profileError);
      return null;
    }

    return profile;
  } catch (err) {
    console.error('getCurrentUserProfile exception:', err);
    return null;
  }
}

function getAvatarUrl(player) {
  if (player.avatar) return player.avatar;
  const name = encodeURIComponent(player.name || player.username || 'User');
  return `https://ui-avatars.com/api/?name=${name}&size=200&background=random&color=fff&bold=true`;
}

// ============================
// Load leaderboard
// ============================
async function loadLeaderboard() {
  try {
    // 1) ดึงข้อมูล user ปัจจุบัน (ถ้ามี)
    currentUserData = await getCurrentUserProfile();

    // 2) ดึง top users เรียงตาม score
    const { data: users, error: usersError } = await supabase
      .from('users')
      .select('user_id, username, display_name, score, avatar')
      .order('score', { ascending: false })
      .limit(50);

    if (usersError) throw usersError;

    const listContainer = document.getElementById('leaderboardList');
    if (!users || users.length === 0) {
      if (listContainer) {
        listContainer.innerHTML = '<div style="text-align:center; padding: 2rem;">No data available</div>';
      }
      leaderboardData = [];
      renderLeaderboard();
      return;
    }

    // 3) รวม user_id และดึงจำนวนโจทย์ที่ solve แล้วใน query เดียว
    const userIds = users.map(u => u.user_id);

    const { data: solvedSubs, error: solvedError } = await supabase
      .from('submissions')
      .select('user_id')
      .eq('is_correct', true)
      .in('user_id', userIds);

    if (solvedError) throw solvedError;

    const solvedMap = {};
    if (solvedSubs) {
      for (const row of solvedSubs) {
        solvedMap[row.user_id] = (solvedMap[row.user_id] || 0) + 1;
      }
    }

    // 4) สร้าง leaderboardData
    leaderboardData = users.map((user, index) => ({
      rank: index + 1,
      user_id: user.user_id,
      name: user.display_name || user.username,
      username: user.username,
      solved: solvedMap[user.user_id] || 0,
      points: user.score || 0,
      avatar: user.avatar || null,
    }));

    // 5) render
    renderLeaderboard();
  } catch (err) {
    console.error('loadLeaderboard error:', err);
    const listContainer = document.getElementById('leaderboardList');
    if (listContainer) {
      listContainer.innerHTML = '<div style="text-align:center; padding: 2rem;">Error loading leaderboard</div>';
    }
  }
}

// ============================
// Render Podium (Top 3)
// ============================
function renderTopThree() {
  const podiumContainer = document.getElementById('podium');
  if (!podiumContainer) return;

  const topThree = leaderboardData.slice(0, 3);
  if (topThree.length === 0) {
    podiumContainer.innerHTML = '<p style="text-align:center; padding:1rem;">No top players yet</p>';
    return;
  }

  const [first, second, third] = topThree;

  let html = '';

  if (second) {
    html += `
      <div class="podium-item second-place">
        <div class="podium-avatar">
          <img src="${getAvatarUrl(second)}" alt="${second.name}" class="avatar-circle" />
          <div class="crown silver">🥈</div>
        </div>
        <div class="podium-info">
          <h3>${second.name}</h3>
          <p class="level">${second.solved} solved</p>
          <p class="xp">${second.points} Points</p>
        </div>
        <div class="podium-base second">
          <div class="rank-number">2</div>
        </div>
      </div>
    `;
  }

  if (first) {
    html += `
      <div class="podium-item first-place">
        <div class="podium-avatar">
          <img src="${getAvatarUrl(first)}" alt="${first.name}" class="avatar-circle" />
          <div class="crown gold">👑</div>
        </div>
        <div class="podium-info">
          <h3>${first.name}</h3>
          <p class="level">${first.solved} solved</p>
          <p class="xp">${first.points} Points</p>
        </div>
        <div class="podium-base first">
          <div class="rank-number">1</div>
        </div>
      </div>
    `;
  }

  if (third) {
    html += `
      <div class="podium-item third-place">
        <div class="podium-avatar">
          <img src="${getAvatarUrl(third)}" alt="${third.name}" class="avatar-circle" />
          <div class="crown bronze">🥉</div>
        </div>
        <div class="podium-info">
          <h3>${third.name}</h3>
          <p class="level">${third.solved} solved</p>
          <p class="xp">${third.points} Points</p>
        </div>
        <div class="podium-base third">
          <div class="rank-number">3</div>
        </div>
      </div>
    `;
  }

  podiumContainer.innerHTML = html;
}

// ============================
// Render list
// ============================
function renderLeaderboardList() {
  const listContainer = document.getElementById('leaderboardList');
  if (!listContainer) return;

  if (!leaderboardData.length) {
    listContainer.innerHTML = '<div style="text-align:center; padding: 2rem;">No leaderboard data</div>';
    return;
  }

  listContainer.innerHTML = leaderboardData
    .map(player => {
      const isCurrentUser =
        currentUserData && player.user_id === currentUserData.user_id;

      return `
        <div class="leaderboard-row ${isCurrentUser ? 'me-row' : ''}">
          <div class="rank-col">
            <span class="rank-number">${player.rank}</span>
          </div>
          <div class="player-col">
            <div class="avatar-wrapper">
              <img src="${getAvatarUrl(player)}" alt="${player.name}" class="avatar-small" />
            </div>
            <div class="player-text">
              <div class="name">
                ${player.name}
                ${isCurrentUser ? '<span class="you-badge">YOU</span>' : ''}
              </div>
              <div class="username">@${player.username}</div>
            </div>
          </div>
          <div class="stats">
            <div class="stat">
              <div class="stat-value">${player.solved}</div>
              <div class="stat-label">Solved</div>
            </div>
            <div class="stat">
              <div class="stat-value">${player.points}</div>
              <div class="stat-label">Points</div>
            </div>
          </div>
        </div>
      `;
    })
    .join('');
}

// ============================
// Render current user widget
// ============================
function renderCurrentUserCard() {
  const currentUserCard = document.querySelector('.current-rank-widget');
  if (!currentUserCard || !currentUserData) {
    if (currentUserCard) currentUserCard.style.display = 'none';
    return;
  }

  const player = leaderboardData.find(p => p.user_id === currentUserData.user_id);

  if (!player) {
    currentUserCard.style.display = 'none';
    return;
  }

  currentUserCard.innerHTML = `
    <div class="rank-widget-header">Current Rank</div>
    <div class="rank-widget-number">#${player.rank}</div>
    <div class="rank-widget-body">
      <div class="rank-widget-name">${player.name}</div>
      <div class="rank-widget-detail">${player.solved} solved • ${player.points} pts</div>
    </div>
  `;
  currentUserCard.style.display = 'block';
}

// ============================
// Master render
// ============================
function renderLeaderboard() {
  renderTopThree();
  renderLeaderboardList();
  renderCurrentUserCard();
}

// ============================
// Init
// ============================
document.addEventListener('DOMContentLoaded', async () => {
  createParticles();
  await setupNavUser();
  await loadLeaderboard();
});
