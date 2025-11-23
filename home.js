import { supabase } from './supabaseClient.js';
import { setupNavUser } from './navAuth.js';

// Create Particles
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

// Animate Stats Counter
function animateValue(element, start, end, duration) {
    if (!element) return;
    
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const value = Math.floor(progress * (end - start) + start);
        element.textContent = value + (element.id === 'totalUsers' || element.id === 'totalSolves' ? '+' : '');
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

// Load Real Statistics from Database
async function loadRealStats() {
    try {
        // 1. Count Active Challenges
        const { count: challengesCount, error: challengesError } = await supabase
            .from('challenges')
            .select('*', { count: 'exact', head: true })
            .eq('is_active', true);

        if (challengesError) throw challengesError;

        // 2. Count Active Users
        const { count: usersCount, error: usersError } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .eq('status', 'active');

        if (usersError) throw usersError;

        // 3. Count Correct Submissions
        const { count: solvesCount, error: solvesError } = await supabase
            .from('submissions')
            .select('*', { count: 'exact', head: true })
            .eq('is_correct', true);

        if (solvesError) throw solvesError;

        // 4. Count Categories (Distinct)
        // Note: Supabase doesn't support distinct count directly in JS easily without RPC or fetching all
        // We will fetch distinct categories
        const { data: categoriesData, error: catError } = await supabase
            .from('challenges')
            .select('category');
            
        let categoriesCount = 0;
        if (!catError && categoriesData) {
            const uniqueCategories = new Set(categoriesData.map(item => item.category));
            categoriesCount = uniqueCategories.size;
        }

        return { 
            totalChallenges: challengesCount || 0, 
            totalUsers: usersCount || 0, 
            totalSolves: solvesCount || 0,
            totalCategories: categoriesCount || 0
        };

    } catch (error) {
        console.error('Error loading stats:', error);
        // Return 0 on error instead of fake data
        return { totalChallenges: 0, totalUsers: 0, totalSolves: 0, totalCategories: 0 };
    }
}

// Intersection Observer for Stats Animation
const observerOptions = {
    threshold: 0.5
};

async function initializeStatsAnimation() {
    const statsSection = document.querySelector('.stats-section');
    if (!statsSection) return;

    // Load real stats
    const stats = await loadRealStats();

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateValue(document.getElementById('totalChallenges'), 0, stats.totalChallenges, 2000);
                animateValue(document.getElementById('totalUsers'), 0, stats.totalUsers, 2000);
                animateValue(document.getElementById('totalSolves'), 0, stats.totalSolves, 2000);
                // ถ้ามี Element สำหรับ category ให้ animate ด้วย (ใน HTML อาจต้องเพิ่ม id)
                const catEl = document.querySelector('.stat-item:nth-child(4) .stat-value');
                if(catEl) animateValue(catEl, 0, stats.totalCategories, 2000);
                
                observer.unobserve(statsSection);
            }
        });
    }, observerOptions);

    observer.observe(statsSection);
}

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    createParticles();
    await setupNavUser();
    await initializeStatsAnimation();
});