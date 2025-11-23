// ============================================
// 1. IMPORTS & GLOBAL STATE
// ============================================
import { supabase } from './supabaseClient.js';
import { setupNavUser } from './navAuth.js';

let currentUser = null;
let dbChallenges = []; // เก็บข้อมูลโจทย์ทั้งหมดจาก DB เพื่อลด Request
let userProgressDB = {}; // เก็บสถานะว่า user ทำข้อไหนไปแล้วบ้าง

// ค่าปรับคะแนนต่อ 1 Hint
const HINT_PENALTY = 10;

// Mapping เชื่อมโยงชื่อ ID ใน HTML (shortId) ให้ตรงกับ Title ใน Database
// Mapping เชื่อมโยงชื่อ ID ใน HTML (shortId) ให้ตรงกับ Title ใน Database
const ID_MAPPING = {
    'sqlInjection': 'SQL Injection Login Bypass',
    'cmdInjection': 'Command Injection Shell',
    'xssStealer': 'XSS Cookie Stealer',
    'jwtHack': 'JWT Token Manipulation',
    'multiCipher': 'Multi-Layer Cipher',
    'xorBrute': 'XOR Brute Force',
    'rsaAttack': 'RSA Small Exponent Attack',
    'customCipher': 'Custom Cipher Breaking',
    'birthdayExif': 'Hidden Birthday Message',
    'geoLocation': 'Geolocation Mystery',
    'stegoFlag': 'Steganography Battlefield',
    'diskAnalysis': 'Disk Analysis',
    'packetBasic': 'Packet Sniffer Basic',
    'dnsTunnel': 'DNS Tunneling Extract',
    'arpSpoof': 'ARP Spoofing Attack',
    'sslStrip': 'SSL Strip Analysis',
    'asmPassword': 'Assembly Password Check',
    'crackme': 'Binary Crackme',
    'obfuscated': 'Obfuscated Code Analysis',
    'malwareAnalysis': 'Malware Behavior Analysis',
    'apkStrings': 'APK String Analysis',
    'rootBypass': 'Root Detection Bypass',
    'sslPinning': 'SSL Pinning Challenge',
    'nativeLib': 'Native Library Reverse'
};
// ใช้ชี้ว่า challenge แต่ละข้อผูกกับ element ID ตัวไหนใน HTML
const FLAG_DOM_CONFIG = {
    sqlInjection: { input: 'sqlInjectionFlag', success: 'sqlSuccess', error: 'sqlError' },
    cmdInjection: { input: 'sqlInjectionFlag', success: 'cmdSuccess', error: 'cmdError' },
    xssStealer:  { input: 'sqlInjectionFlag', success: 'xssSuccess', error: 'xssError' },
    jwtHack:     { input: 'sqlInjectionFlag', success: 'jwtSuccess', error: 'jwtError' },

    multiCipher: { input: 'multiCipherFlag', success: 'multiSuccess', error: 'multiError' },

    xorBrute:    { input: 'xorKnownFlag', success: 'xorSuccess', error: 'xorError' },
    rsaAttack:   { input: 'xorKnownFlag', success: 'rsaSuccess', error: 'rsaError' },
    customCipher:{ input: 'xorKnownFlag', success: 'customSuccess', error: 'customError' },

    birthdayExif:{ input: 'birthdayExifFlag', success: 'birthdaySuccess', error: 'birthdayError' },
    geoLocation: { input: 'geoLocationFlag',  success: 'geoSuccess',      error: 'geoError' },
    stegoFlag:   { input: 'stegoFlagFlag',    success: 'stegoSuccess',    error: 'stegoError' },
    diskAnalysis:{ input: 'diskAnalysisFlag', success: 'diskSuccess',     error: 'diskError' },

    packetBasic: { input: 'packetBasicFlag',  success: 'packetSuccess',   error: 'packetError' },
    dnsTunnel:   { input: 'dnsTunnelFlag',    success: 'dnsSuccess',      error: 'dnsError' },
    arpSpoof:    { input: 'arpSpoofFlag',     success: 'arpSuccess',      error: 'arpError' },
    sslStrip:    { input: 'sslStripFlag',     success: 'sslSuccess',      error: 'sslError' },

    asmPassword: { input: 'asmPasswordFlag',  success: 'asmSuccess',      error: 'asmError' },
    crackme:     { input: 'crackmeFlag',      success: 'crackmeSuccess',  error: 'crackmeError' },
    obfuscated:  { input: 'obfuscatedFlag',   success: 'obfuscatedSuccess', error: 'obfuscatedError' },

    malwareAnalysis: { input: 'malwareAnalysisFlag', success: 'malwareSuccess', error: 'malwareError' },

    apkStrings:  { input: 'apkAnalysisFlag',  success: 'apkSuccess',      error: 'apkError' },
    rootBypass:  { input: 'rootDetectionFlag', success: 'rootSuccess',    error: 'rootError' },
    sslPinning:  { input: 'sslPinningFlag',   success: 'sslPinSuccess',   error: 'sslPinError' },

    nativeLib:   { input: 'nativeLibFlag',    success: null,              error: 'nativeError' }
};

// mapping prefix ของ hint → shortId ของ challenge
const LEGACY_MAP = {
    'sql': 'sqlInjection',
    'cmd': 'cmdInjection',
    'xss': 'xssStealer',
    'jwt': 'jwtHack',
    'multi': 'multiCipher',
    'xor': 'xorBrute',
    'rsa': 'rsaAttack',
    'custom': 'customCipher',
    'birthday': 'birthdayExif',
    'geo': 'geoLocation',
    'stego': 'stegoFlag',
    'disk': 'diskAnalysis',
    'packet': 'packetBasic',
    'dns': 'dnsTunnel',
    'arp': 'arpSpoof',
    'ssl': 'sslStrip',
    'asm': 'asmPassword',
    'crackme': 'crackme', // ชื่อเหมือนเดิม
    'obfuscated': 'obfuscated', // ชื่อเหมือนเดิม
    'malware': 'malwareAnalysis',
    'apk': 'apkStrings',
    'root': 'rootBypass',
    'sslPin': 'sslPinning',
    'native': 'nativeLib'
};

// ============================================
// 2. INITIALIZATION
// ============================================
document.addEventListener('DOMContentLoaded', async () => {
    console.log("🚀 Initializing Challenge System...");
    
    // 1. Setup Navbar & Auth
    await setupNavUser();
    
    // 2. Get Current User Data
    const { data: { session } } = await supabase.auth.getSession();
    if (session?.user) {
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('email', session.user.email)
            .single();
        currentUser = user;
        
        // Load Solved Challenges
        await loadUserProgress();
    }

    // 3. Load All Challenges from DB
    const { data: challenges, error } = await supabase
        .from('challenges')
        .select('*');
        
    if (!error && challenges) {
        dbChallenges = challenges;
    }

    createParticles();
    updatePointsDisplay(); // Update UI points
});

async function loadUserProgress() {
    if (!currentUser) return;
    const { data } = await supabase
        .from('submissions')
        .select('challenge_id, is_correct')
        .eq('user_id', currentUser.user_id)
        .eq('is_correct', true);
        
    if (data) {
        // เก็บ ID ของโจทย์ที่ทำได้แล้ว
        userProgressDB = data.reduce((acc, sub) => {
            acc[sub.challenge_id] = true;
            return acc;
        }, {});
    }
}

// ============================================
// 3. CORE FUNCTIONS (LOGIC)
// ============================================

// --- 3.1 CHECK FLAG (DATABASE) ---
// ============================================
// SECURE CHECK FLAG (Database Verification)
// ============================================
window.checkFlag = async function(shortId) {
    // 1. Check Login
    if (!currentUser) {
        showNotification('⚠️ กรุณาเข้าสู่ระบบก่อนส่งคำตอบ', 'warning');
        return;
    }

    // 2. Get Input Value
    const domCfg   = FLAG_DOM_CONFIG[shortId] || {};
    const inputId  = domCfg.input   || `${shortId}Flag`;
    const successId= domCfg.success || `${shortId}Success`;
    const errorId  = domCfg.error   || `${shortId}Error`;

    const inputEl   = document.getElementById(inputId);
    const successMsg= successId ? document.getElementById(successId) : null;
    const errorMsg  = errorId ? document.getElementById(errorId) : null;

    if (!inputEl) {
        console.error(`Flag input element not found for shortId=${shortId}, tried id=${inputId}`);
        showNotification('Error: flag input not found for this challenge', 'error');
        return;
    }
    const userFlag = inputEl.value.trim();
    if (!userFlag) {
        if(errorMsg) {
            errorMsg.style.display = 'block';
            errorMsg.textContent = '⚠️ กรุณาใส่ Flag';
            setTimeout(() => errorMsg.style.display = 'none', 3000);
        }
        return;
    }

    // 3. Find Challenge in DB
    const targetTitle = ID_MAPPING[shortId];
    const dbChallenge = dbChallenges.find(c => c.title === targetTitle);

    if (!dbChallenge) {
        console.error(`Challenge not found in DB: ${targetTitle}`);
        showNotification('Error: Challenge data mismatch', 'error');
        return;
    }

    // 4. Verify Flag (Compare with DB)
    // Note: In a production app, you might send the flag to a Postgres function 
    // or Edge Function to check, but checking against loaded data is step 1 for this architecture.
    const isCorrect = (userFlag === dbChallenge.flag);

    try {
        // 5. Count Used Hints from DB
        const { count: hintsUsed } = await supabase
            .from('user_hints')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', currentUser.user_id)
            .eq('challenge_id', dbChallenge.challenge_id);

        // 6. Calculate Score
        const penalty = (hintsUsed || 0) * HINT_PENALTY;
        const finalPoints = Math.max(0, dbChallenge.score_base - penalty);

        // 7. Save Submission
        // Check if already solved to prevent point farming
        const alreadySolved = userProgressDB[dbChallenge.challenge_id];

        const { error } = await supabase.from('submissions').insert({
            user_id: currentUser.user_id,
            challenge_id: dbChallenge.challenge_id,
            flag_submitted: userFlag,
            is_correct: isCorrect,
            points: (isCorrect && !alreadySolved) ? finalPoints : 0,
            hints_used: hintsUsed || 0
        });

        if (error) throw error;

        // 8. Update UI & User Score
        if (isCorrect) {
            if (!alreadySolved) {
                // Update User Total Score
                const newTotalScore = (currentUser.score || 0) + finalPoints;
                await supabase.from('users').update({ score: newTotalScore }).eq('user_id', currentUser.user_id);
                currentUser.score = newTotalScore;
                userProgressDB[dbChallenge.challenge_id] = true;

                const { error: userUpdateError } = await supabase
                .from('users')
                .update({ score: newTotalScore })
                .eq('user_id', currentUser.user_id);

            if (userUpdateError) {
                console.error('User score update error:', userUpdateError);
            }

            }

            if (successMsg) {
                successMsg.style.display = 'block';
                if (alreadySolved) {
                    successMsg.innerHTML = `🎉 ถูกต้อง! (คุณทำข้อนี้ไปแล้ว)`;
                } else {
                    successMsg.innerHTML = `🎉 ถูกต้อง! +${finalPoints} คะแนน<br>
                        <small style="color: var(--gray);">(Hint used: ${hintsUsed}, Penalty: -${penalty})</small>`;
                }
            }
            if (errorMsg) errorMsg.style.display = 'none';
            showNotification(`Challenge Solved!`, 'success');
            updatePointsDisplay();

        } else {
            if (successMsg) successMsg.style.display = 'none';
            if (errorMsg) {
                errorMsg.style.display = 'block';
                errorMsg.textContent = '❌ Flag ไม่ถูกต้อง';
                setTimeout(() => errorMsg.style.display = 'none', 3000);
            }
        }

    } catch (err) {
        console.error('Submission Error:', err);
        showNotification('เกิดข้อผิดพลาดในการเชื่อมต่อ', 'error');
    }
};

// --- 3.2 HINT SYSTEM (DATABASE) ---
window.toggleHint = async function(hintId) {
    if (!currentUser) {
        showNotification('⚠️ กรุณาเข้าสู่ระบบเพื่อใช้ Hint', 'warning');
        return;
    }

    const hintEl = document.getElementById(hintId);
    if (!hintEl) {
        console.error("Hint Element Not Found:", hintId);
        return;
    }

    if (hintEl.style.display === 'block') {
        hintEl.style.display = 'none';
        return;
    }

    // Parse ID: "xsshint1" -> rawId="xss", hintNumber=1
    const matches = hintId.match(/^(.+?)hint(\d+)$/);
    if (!matches) {
        // Fallback: ถ้าไม่ตรง pattern ให้เปิดเลย (กัน error)
        hintEl.style.display = 'block';
        return;
    }

    const rawId = matches[1];
    const hintNumber = parseInt(matches[2]);

    // แปลงชื่อย่อ (xss) เป็นชื่อจริง (xssStealer)
    const realInteractiveId = LEGACY_MAP[rawId] || rawId;

    showHintConfirmation(hintId, HINT_PENALTY, async () => {
        // 1. เปิด Hint ทันที (UI Feedback)
        hintEl.style.display = 'block';

        // 2. หา Challenge ใน DB ด้วย ID ที่แปลงแล้ว
        const dbChallenge = dbChallenges.find(c => c.interactive_id === realInteractiveId);

        if (dbChallenge) {
            try {
                // หา hint_id จากตาราง hints (ต้องมีข้อมูลในตาราง hints ก่อน)
                const { data: hintData } = await supabase
                    .from('hints')
                    .select('hint_id')
                    .eq('challenge_id', dbChallenge.challenge_id)
                    .eq('order_index', hintNumber)
                    .single();

                // บันทึกการใช้ Hint
                const { error } = await supabase.from('user_hints').insert({
                    user_id: currentUser.user_id,
                    challenge_id: dbChallenge.challenge_id,
                    hint_id: hintData?.hint_id || null // ถ้าหา hint_id ไม่เจอก็ส่ง null ไปก่อน (ถ้า DB ยอม)
                });
                
                if (error && error.code !== '23505') { // 23505 = Duplicate (เคยกดแล้ว)
                    console.warn("Hint DB log error:", error.message);
                }

            } catch (err) {
                console.error("Hint Logic Error:", err);
            }
        } else {
            console.warn(`Challenge not found in DB for interactive_id: ${realInteractiveId} (raw: ${rawId})`);
        }
    });
};


// --- 3.3 MODAL OPENER ---
window.openInteractiveChallenge = function(shortId) {
    // หา HTML Content
    const content = interactiveChallenges[shortId]?.content;
    
    if (!content) {
        alert('Error: Challenge content not found for ' + shortId);
        return;
    }

    // Inject HTML
    const container = document.getElementById('interactiveContent');
    container.innerHTML = content;

    // Show Modal
    document.getElementById('interactiveModal').classList.add('active');
    
    // Update Score Display in Modal (if element exists)
    if (currentUser) {
        const pointsEl = container.querySelector('.current-points');
        if (pointsEl) pointsEl.textContent = currentUser.score;
    }
};

// ============================================
// 4. HTML CONTENT TEMPLATES (The Massive Object)
// ============================================
// เก็บ HTML เดิมไว้ เพื่อให้ UI ไม่พัง
const interactiveChallenges = {
    sqlInjection: {
            content: `
                <h2 style="color: var(--primary); margin-bottom: 1rem;">🌐 SQL Injection Login Bypass</h2>
                
                <div class="analysis-results">
                    <h4>🎯 Mission Objective</h4>
                    <p>ระบบ SecureBank มีช่องโหว่ SQL Injection ที่ซับซ้อน ต้องใช้เทคนิคขั้นสูงในการ bypass</p>
                    <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                        <li>ระบบมี basic filter ที่ block คำสั่ง SQL ทั่วไป</li>
                        <li>ต้องใช้ technique เช่น comment bypass, case manipulation</li>
                        <li>แต่ละ attempt จะมี feedback ช่วยในการ debug</li>
                    </ul>
                </div>

                <div class="hints-section">
                    <div class="hints-warning">⚠️ Each hint costs 10 points</div>
                    <div class="hints-stats">
                        <span>Current Points: <span class="current-points">100</span></span>
                        <span style="margin-left: 1rem;">Attempts: <span id="sqlAttempts">0</span>/10</span>
                    </div>
                </div>

                <div class="sql-interface">
                    <div class="login-panel">
                        <div class="panel-header">
                            <div class="status-indicator"></div>
                            <span>SecureBank Authentication System v3.2</span>
                        </div>
                        
                        <div class="login-form">
                            <div class="form-group">
                                <label>👤 Username</label>
                                <input type="text" id="sqlUser" placeholder="Enter username" 
                                    style="background: rgba(0,0,0,0.6); border: 2px solid var(--primary); 
                                    color: var(--light); padding: 0.8rem; width: 100%; border-radius: 8px;
                                    font-family: 'Courier New', monospace;">
                            </div>
                            
                            <div class="form-group">
                                <label>🔑 Password</label>
                                <input type="password" id="sqlPass" placeholder="Enter password"
                                    style="background: rgba(0,0,0,0.6); border: 2px solid var(--primary); 
                                    color: var(--light); padding: 0.8rem; width: 100%; border-radius: 8px;
                                    font-family: 'Courier New', monospace;">
                            </div>
                            
                            <button onclick="attemptSQLLogin()" class="login-btn">
                                <span>LOGIN</span>
                            </button>
                        </div>
                        
                        <div id="sqlResult" class="result-panel"></div>
                    </div>

                    <div class="debug-panel">
                        <div class="debug-header">🔍 Query Debug Panel</div>
                        <div id="sqlDebug" class="debug-content">
                            <p style="color: var(--gray);">Query information will appear here...</p>
                        </div>
                    </div>

                    <div class="filter-panel">
                        <div class="filter-header">🛡️ Active Security Filters</div>
                        <div class="filter-content">
                            <div class="filter-item">❌ Blocked: <code>OR</code>, <code>AND</code> (case-sensitive)</div>
                            <div class="filter-item">❌ Blocked: <code>--</code> (double dash)</div>
                            <div class="filter-item">❌ Blocked: <code>/*</code> (C-style comment start)</div>
                            <div class="filter-item">✅ Allowed: Single quotes, special chars</div>
                            <div class="filter-item" style="color: var(--warning);">⚠️ Hint: Think about bypass techniques...</div>
                        </div>
                    </div>
                </div>

                <div class="hint-box">
                    <button class="hint-btn" onclick="toggleHint('sqlhint1')">💡 Hint 1: Filter Analysis</button>
                    <div id="sqlhint1" class="hint-content" style="display:none;">
                        Filters block: OR, AND, --, /*<br>
                        But they're case-sensitive!<br>
                        Try: Or, oR, AnD, etc.<br>
                        Or use alternative comment: #
                    </div>

                    <button class="hint-btn" onclick="toggleHint('sqlhint2')">💡 Hint 2: Query Structure</button>
                    <div id="sqlhint2" class="hint-content" style="display:none;">
                        Query: SELECT * FROM users WHERE username='[INPUT]' AND password='[INPUT]'<br>
                        Goal: Make it return TRUE without knowing password<br>
                        Example: admin' oR '1'='1' # <br>
                        (lowercase 'o' and 'R' bypass filter)
                    </div>

                    <button class="hint-btn" onclick="toggleHint('sqlhint3')">💡 Hint 3: Working Payload</button>
                    <div id="sqlhint3" class="hint-content" style="display:none;">
                        Username: admin' oR '1'='1' #<br>
                        Password: (anything)<br>
                        Or try: admin' || 1=1 #<br>
                        The # comments out the rest of the query
                    </div>
                </div>

                <div class="flag-input">
                    <input type="text" id="sqlInjectionFlag" placeholder="CTF{...}">
                    <button class="submit-btn" onclick="checkFlag('sqlInjection')">Submit Flag</button>
                </div>
                <div class="success-message" id="sqlSuccess">🎉 Correct! Challenge Completed!</div>
                <div class="error-message" id="sqlError">❌ Incorrect flag. Try again!</div>
            `
        },
            //Web 2
            cmdInjection: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">🌐 Command Injection Shell</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>Web application มี ping utility ที่มีช่องโหว่ command injection</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>Inject OS commands เพื่อ explore filesystem</li>
                            <li>หาไฟล์ flag.txt ในระบบ</li>
                            <li>อ่านเนื้อหาไฟล์เพื่อเอา flag</li>
                        </ul>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output">Network Diagnostic Tool
========================

Ping Target: <input type="text" id="cmdInput" placeholder="127.0.0.1" style="background: transparent; border: 1px solid var(--primary); color: var(--light); padding: 0.5rem; width: 300px; border-radius: 5px;">

<button onclick="executeCMD()" style="background: var(--primary); color: var(--dark); border: none; padding: 0.6rem 1.5rem; border-radius: 5px; cursor: pointer; font-weight: bold; margin-top: 0.5rem;">PING</button>

<div id="cmdResult" style="margin-top: 1rem;"></div></div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('cmdhint1')">💡 Hint 1: Command Chaining</button>
                        <div id="cmdhint1" class="hint-content">
                            ใช้ ; && || | เพื่อ chain commands<br>
                            ตัวอย่าง: 127.0.0.1; ls -la
                        </div>

                        <button class="hint-btn" onclick="toggleHint('cmdhint2')">💡 Hint 2: File Discovery</button>
                        <div id="cmdhint2" class="hint-content">
                            ใช้ ls เพื่อดู files<br>
                            ใช้ find เพื่อค้นหาไฟล์: find . -name "*.txt"
                        </div>

                        <button class="hint-btn" onclick="toggleHint('cmdhint3')">💡 Hint 3: Reading Files</button>
                        <div id="cmdhint3" class="hint-content">
                            ใช้ cat เพื่ออ่านไฟล์: cat flag.txt<br>
                            หรือใช้ more, less, head, tail
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="sqlInjectionFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('cmdInjection')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="cmdSuccess">🎉 Correct! You got remote command execution!</div>
                    <div class="error-message" id="cmdError">❌ Incorrect flag. Keep exploring the filesystem!</div>
                `
            },
            //Web 3
            xssStealer: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">🌐 XSS Cookie Stealer</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>Comment system มีช่องโหว่ XSS แต่มี filter ที่ต้อง bypass</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>ทดสอบ XSS payloads ที่ซับซ้อน</li>
                            <li>Bypass XSS filter (blocked: &lt;script&gt;, onerror, onclick)</li>
                            <li>Steal admin cookie เพื่อเข้าถึง admin panel</li>
                        </ul>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output">Comment System
===============

Your Comment: <textarea id="xssInput" style="background: transparent; border: 1px solid var(--primary); color: var(--light); padding: 0.5rem; width: 100%; height: 80px; border-radius: 5px; font-family: monospace;"></textarea>

<button onclick="submitXSS()" style="background: var(--primary); color: var(--dark); border: none; padding: 0.6rem 1.5rem; border-radius: 5px; cursor: pointer; font-weight: bold; margin-top: 0.5rem;">POST COMMENT</button>

<div id="xssResult" style="margin-top: 1rem;"></div>
<div id="xssPreview" style="margin-top: 1rem; padding: 1rem; border: 1px solid var(--secondary); border-radius: 5px; min-height: 50px;"></div></div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('xsshint1')">💡 Hint 1: Filter Bypass</button>
                        <div id="xsshint1" class="hint-content">
                            &lt;script&gt; tag ถูก block แต่ลองใช้ event handlers อื่นๆ<br>
                            ตัวอย่าง: &lt;img src=x onload=alert(1)&gt;
                        </div>

                        <button class="hint-btn" onclick="toggleHint('xsshint2')">💡 Hint 2: Alternative Tags</button>
                        <div id="xsshint2" class="hint-content">
                            ลองใช้ &lt;svg&gt;, &lt;iframe&gt;, &lt;body&gt; tags<br>
                            ตัวอย่าง: &lt;svg/onload=alert(document.cookie)&gt;
                        </div>

                        <button class="hint-btn" onclick="toggleHint('xsshint3')">💡 Hint 3: Cookie Extraction</button>
                        <div id="xsshint3" class="hint-content">
                            ใช้ document.cookie เพื่อเข้าถึง cookies<br>
                            Admin cookie format: admin_session=FLAG_HERE
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="sqlInjectionFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('xssStealer')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="xssSuccess">🎉 Correct! You successfully stole the admin cookie!</div>
                    <div class="error-message" id="xssError">❌ Incorrect flag. Try different XSS payloads!</div>
                `
            },
            //Web 4
            jwtHack: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">🌐 JWT Token Manipulation</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>API ใช้ JWT tokens แต่มีช่องโหว่ algorithm confusion vulnerability</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>วิเคราะห์ JWT token structure</li>
                            <li>เปลี่ยน algorithm จาก RS256 เป็น HS256</li>
                            <li>Modify payload เพื่อเป็น admin และ sign ด้วย public key</li>
                        </ul>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output">JWT Token Inspector
====================

Your Token:
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjMzMDI0ODAwfQ.signature

Decoded Header: {"alg":"RS256","typ":"JWT"}
Decoded Payload: {"user":"user","role":"user","iat":1633024800}

<textarea id="jwtInput" placeholder="Paste modified JWT here..." style="background: transparent; border: 1px solid var(--primary); color: var(--light); padding: 0.5rem; width: 100%; height: 100px; border-radius: 5px; font-family: monospace; margin-top: 1rem;"></textarea>

<button onclick="verifyJWT()" style="background: var(--primary); color: var(--dark); border: none; padding: 0.6rem 1.5rem; border-radius: 5px; cursor: pointer; font-weight: bold; margin-top: 0.5rem;">VERIFY TOKEN</button>

<div id="jwtResult" style="margin-top: 1rem;"></div></div>
                    </div>

                    <div class="tool-section">
                        <h4>🔧 JWT Tools</h4>
                        <button class="tool-btn" onclick="decodeJWT()">Decode JWT</button>
                        <button class="tool-btn" onclick="showPublicKey()">Show Public Key</button>
                        <button class="tool-btn" onclick="createHS256()">Create HS256 Token</button>
                        <div id="toolOutput" style="margin-top: 1rem; font-family: monospace; color: var(--secondary);"></div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('jwthint1')">💡 Hint 1: Algorithm Confusion</button>
                        <div id="jwthint1" class="hint-content">
                            RS256 ใช้ private key sign และ public key verify<br>
                            HS256 ใช้ shared secret สำหรับทั้ง sign และ verify<br>
                            ถ้าเปลี่ยนเป็น HS256 server อาจใช้ public key เป็น secret!
                        </div>

                        <button class="hint-btn" onclick="toggleHint('jwthint2')">💡 Hint 2: Payload Modification</button>
                        <div id="jwthint2" class="hint-content">
                            เปลี่ยน "role":"user" เป็น "role":"admin"<br>
                            จากนั้น sign ด้วย public key โดยใช้ HS256 algorithm
                        </div>

                        <button class="hint-btn" onclick="toggleHint('jwthint3')">💡 Hint 3: Token Format</button>
                        <div id="jwthint3" class="hint-content">
                            JWT format: base64(header).base64(payload).base64(signature)<br>
                            ใช้ tools ด้านบนช่วยสร้าง token ที่ถูกต้อง
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="sqlInjectionFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('jwtHack')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="jwtSuccess">🎉 Correct! You exploited the JWT vulnerability!</div>
                    <div class="error-message" id="jwtError">❌ Incorrect flag. Try manipulating the JWT token!</div>
                `
            },
            //Crypto 1
            multiCipher: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">🔐 Multi-Layer Cipher</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>ข้อความถูกเข้ารหัสด้วย 3 layers: Caesar → Base64 → ROT13</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>ถอดรหัสทีละชั้นในลำดับที่ถูกต้อง</li>
                            <li>ใช้เครื่องมือด้านล่างช่วยในการถอดรหัส</li>
                            <li>หา flag ที่ซ่อนอยู่ในข้อความ</li>
                        </ul>
                    </div>

                    <div class="cipher-box">
                        <h4 style="color: var(--purple);">Encrypted Message:</h4>
                        <p style="font-size: 1.1rem; margin-top: 0.5rem;">
                        FrpKcyber{p3e4_y4l3e_qrpelcg_z4fgre}
                        </p>
                    </div>

                    <div class="tool-section">
                        <h4>🔧 Decryption Tools</h4>
                        <div style="margin: 1rem 0;">
                            <input type="text" id="cipherInput" placeholder="Enter encrypted text..." style="background: rgba(0,0,0,0.8); border: 1px solid var(--primary); color: var(--light); padding: 0.5rem; width: 100%; border-radius: 5px; font-family: monospace;">
                        </div>
                        <button class="tool-btn" onclick="decodeROT13()">ROT13 Decode</button>
                        <button class="tool-btn" onclick="decodeBase64Cipher()">Base64 Decode</button>
                        <button class="tool-btn" onclick="decodeCaesar()">Caesar Decode (shift 3)</button>
                        <button class="tool-btn" onclick="decodeAll()">Auto Decode All</button>
                        <div id="cipherOutput" style="margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.8); border: 1px solid var(--secondary); border-radius: 5px; font-family: monospace; min-height: 50px;"></div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('cryptohint1')">💡 Hint 1: Decryption Order</button>
                        <div id="cryptohint1" class="hint-content">
                            การเข้ารหัส: Plaintext → Caesar → Base64 → ROT13<br>
                            การถอดรหัส: ต้องทำย้อนกลับ ROT13 → Base64 → Caesar
                        </div>

                        <button class="hint-btn" onclick="toggleHint('cryptohint2')">💡 Hint 2: ROT13 First</button>
                        <div id="cryptohint2" class="hint-content">
                            เริ่มจาก ROT13 ก่อน (rotate ตัวอักษร 13 ตำแหน่ง)<br>
                            A→N, B→O, C→P, ... , N→A, O→B, P→C
                        </div>

                        <button class="hint-btn" onclick="toggleHint('cryptohint3')">💡 Hint 3: Caesar Shift</button>
                        <div id="cryptohint3" class="hint-content">
                            Caesar cipher ในที่นี้ใช้ shift = 3<br>
                            D→A, E→B, F→C, G→D, etc.
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="multiCipherFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('multiCipher')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="multiSuccess">🎉 Correct! You decoded all cipher layers!</div>
                    <div class="error-message" id="multiError">❌ Incorrect flag. Try decoding in the right order!</div>
                `
            },
            //Crypto 2
            xorBrute: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">🔐 XOR Brute Force</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>ข้อความถูกเข้ารหัสด้วย XOR single-byte key (0x00-0xFF)</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>Brute force ทุกค่า key ที่เป็นไปได้ (256 keys)</li>
                            <li>หาผลลัพธ์ที่เป็น readable English text</li>
                            <li>Flag จะอยู่ในรูปแบบ secXplore{...}</li>
                        </ul>
                    </div>

                    <div class="cipher-box">
                        <h4 style="color: var(--purple);">Encrypted Hex:</h4>
                        <p style="font-size: 1rem; margin-top: 0.5rem; word-break: break-all;">
                        1c060b59121b0d1612461a5d4c1a0d465b0e0b1a5d454c0d</p>
                    </div>

                    <div class="tool-section">
                        <h4>🔧 XOR Brute Force Tool</h4>
                        <div style="margin: 1rem 0;">
                            <label>XOR Key (hex): <input type="text" id="xorKey" placeholder="00-FF" maxlength="2" style="background: rgba(0,0,0,0.8); border: 1px solid var(--primary); color: var(--light); padding: 0.5rem; width: 100px; border-radius: 5px; font-family: monospace;"></label>
                            <button class="tool-btn" onclick="xorDecrypt()">Decrypt with Key</button>
                            <button class="tool-btn" onclick="xorBruteForce()">Brute Force All Keys</button>
                        </div>
                        <div id="xorOutput" style="margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.8); border: 1px solid var(--secondary); border-radius: 5px; font-family: monospace; max-height: 300px; overflow-y: auto;"></div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('xorhint1')">💡 Hint 1: XOR Properties</button>
                        <div id="xorhint1" class="hint-content">
                            XOR เป็น symmetric cipher: plaintext XOR key = ciphertext<br>
                            ciphertext XOR key = plaintext<br>
                            ถ้า XOR ด้วย key เดียวกัน 2 ครั้ง จะได้ข้อความเดิม
                        </div>

                        <button class="hint-btn" onclick="toggleHint('xorhint2')">💡 Hint 2: Brute Force Strategy</button>
                        <div id="xorhint2" class="hint-content">
                            มี key เพียง 256 ตัว (0x00 ถึง 0xFF)<br>
                            ลอง XOR ด้วยทุก key และหาผลที่อ่านได้<br>
                            ข้อความที่ถูกต้องจะมี readable ASCII characters
                        </div>

                        <button class="hint-btn" onclick="toggleHint('xorhint3')">💡 Hint 3: Flag Format</button>
                        <div id="xorhint3" class="hint-content">
                            Flag เริ่มต้นด้วย "secXplore{"<br>
                            ใช้ข้อมูลนี้ช่วยหา key ที่ถูกต้อง<br>
                            ถ้า ciphertext[0] XOR 's' = key
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="xorKnownFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('xorBrute')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="xorSuccess">🎉 Correct! You cracked the XOR encryption!</div>
                    <div class="error-message" id="xorError">❌ Incorrect flag. Try brute forcing all keys!</div>
                `
            },

            //Crypto 3
            rsaAttack: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">🔐 RSA Small Exponent Attack</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>RSA encryption ใช้ e=3 และมี 3 ciphertext ของข้อความเดียวกัน</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>ใช้ Chinese Remainder Theorem (CRT) หา m³</li>
                            <li>คำนวณ cube root เพื่อหา plaintext</li>
                            <li>Decode ข้อความเพื่อหา flag</li>
                        </ul>
                    </div>

                    <div class="cipher-box">
                        <h4 style="color: var(--purple);">RSA Parameters:</h4>
                        <div style="text-align: left; margin-top: 1rem; font-size: 0.9rem;">
                            <p><strong>e = 3</strong></p>
                            <p style="margin-top: 0.5rem;"><strong>n1 =</strong> 95642412847883940786305809307353693569</p>
                            <p><strong>c1 =</strong> 12345678901234567890123456789012345678</p>
                            <p style="margin-top: 0.5rem;"><strong>n2 =</strong> 117459929787100018763388685239228564389</p>
                            <p><strong>c2 =</strong> 23456789012345678901234567890123456789</p>
                            <p style="margin-top: 0.5rem;"><strong>n3 =</strong> 122656808337815211204693407655668838229</p>
                            <p><strong>c3 =</strong> 34567890123456789012345678901234567890</p>
                        </div>
                    </div>

                    <div class="tool-section">
                        <h4>🔧 RSA Attack Tools</h4>
                        <button class="tool-btn" onclick="calculateCRT()">Calculate CRT</button>
                        <button class="tool-btn" onclick="calculateCubeRoot()">Calculate Cube Root</button>
                        <button class="tool-btn" onclick="convertToText()">Convert to Text</button>
                        <div id="rsaOutput" style="margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.8); border: 1px solid var(--secondary); border-radius: 5px; font-family: monospace; max-height: 300px; overflow-y: auto;"></div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('rsahint1')">💡 Hint 1: Small Exponent Attack</button>
                        <div id="rsahint1" class="hint-content">
                            เมื่อ e=3 และมีข้อความเดียวกันถูกเข้ารหัสด้วย public key ต่างกัน 3 ตัว<br>
                            เราสามารถใช้ CRT หา m³ mod (n1*n2*n3)<br>
                            ถ้า m³ < n1*n2*n3 เราหา cube root ได้โดยตรง
                        </div>

                        <button class="hint-btn" onclick="toggleHint('rsahint2')">💡 Hint 2: Chinese Remainder Theorem</button>
                        <div id="rsahint2" class="hint-content">
                            CRT formula: x ≡ c1 (mod n1), x ≡ c2 (mod n2), x ≡ c3 (mod n3)<br>
                            Solution: x = Σ(ci * Mi * yi) mod N<br>
                            Where N = n1*n2*n3, Mi = N/ni, yi = Mi⁻¹ mod ni
                        </div>

                        <button class="hint-btn" onclick="toggleHint('rsahint3')">💡 Hint 3: Cube Root </div>
                        <button class="hint-btn" onclick="toggleHint('rsahint3')">💡 Hint 3: Cube Root Calculation</button>
                        <div id="rsahint3" class="hint-content">
                            หลังจากได้ m³ แล้ว ให้คำนวณ cube root<br>
                            m = ∛(m³)<br>
                            แปลง m เป็น bytes แล้ว decode เป็น text
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="xorKnownFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('rsaWeak')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="rsaSuccess">🎉 Correct! You broke RSA with small exponent!</div>
                    <div class="error-message" id="rsaError">❌ Incorrect flag. Check your CRT calculation!</div>
                `
            },
            //Crypto 4
            customCipher: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">🔐 Custom Cipher Breaking</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>Custom encryption algorithm ที่มีจุดอ่อนในการ implement</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>วิเคราะห์ algorithm จาก encryption code</li>
                            <li>หาจุดอ่อนในการเข้ารหัส</li>
                            <li>สร้าง decryption algorithm เพื่อถอดรหัส</li>
                        </ul>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output">Custom Encryption Algorithm
        =============================

        def encrypt(plaintext, key):
            result = ""
            for i, char in enumerate(plaintext):
                shift = (ord(key[i % len(key)]) + i) % 26
                if char.isupper():
                    result += chr((ord(char) - 65 + shift) % 26 + 65)
                elif char.islower():
                    result += chr((ord(char) - 97 + shift) % 26 + 97)
                else:
                    result += char
            return result

        Key: "CTF"
        Encrypted: Ugfaqnver{e9v7qz_p8rjvu_dv3mk_hupvqv3r}</div>
                    </div>

                    <div class="tool-section">
                        <h4>🔧 Decryption Tools</h4>
                        <div style="margin: 1rem 0;">
                            <label>Key: <input type="text" id="customKey" value="CTF" style="background: rgba(0,0,0,0.8); border: 1px solid var(--primary); color: var(--light); padding: 0.5rem; width: 150px; border-radius: 5px; margin-left: 0.5rem;"></label>
                        </div>
                        <div style="margin: 1rem 0;">
                            <textarea id="customCiphertext" style="background: rgba(0,0,0,0.8); border: 1px solid var(--primary); color: var(--light); padding: 0.5rem; width: 100%; height: 80px; border-radius: 5px; font-family: monospace;" placeholder="Enter ciphertext...">Ugfaqnvier{e9v7qz_p8rjvu_dv3mk_hupvqv3r}</textarea>
                        </div>
                        <button class="tool-btn" onclick="decryptCustom()">Decrypt</button>
                        <button class="tool-btn" onclick="analyzeCustom()">Analyze Algorithm</button>
                        <div id="customOutput" style="margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.8); border: 1px solid var(--secondary); border-radius: 5px; font-family: monospace; max-height: 300px; overflow-y: auto;"></div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('customhint1')">💡 Hint 1: Algorithm Analysis</button>
                        <div id="customhint1" class="hint-content">
                            Algorithm ใช้ key แบบ repeating และ position-dependent shift<br>
                            shift = (ord(key[i % len(key)]) + i) % 26<br>
                            เป็น Vigenere cipher แบบ modified
                        </div>

                        <button class="hint-btn" onclick="toggleHint('customhint2')">💡 Hint 2: Decryption Process</button>
                        <div id="customhint2" class="hint-content">
                            เพื่อถอดรหัส ต้อง reverse operation:<br>
                            plaintext_char = (ciphertext_char - shift) % 26<br>
                            ใช้ key เดียวกันและ position index
                        </div>

                        <button class="hint-btn" onclick="toggleHint('customhint3')">💡 Hint 3: Implementation</button>
                        <div id="customhint3" class="hint-content">
                            สำหรับแต่ละตัวอักษร:<br>
                            1. คำนวณ shift = (ord(key[i % len(key)]) + i) % 26<br>
                            2. ลบ shift จาก ciphertext character<br>
                            3. Handle uppercase/lowercase และ non-alphabetic characters
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="xorKnownFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('customCipher')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="customSuccess">🎉 Correct! You broke the custom cipher!</div>
                    <div class="error-message" id="customError">❌ Incorrect flag. Check your decryption algorithm!</div>
                `
            },
            //Forensic 1
            birthdayExif: {
                content: `
                <h2 style="color: var(--primary); margin-bottom: 1rem;">🔍 Hidden Birthday Message</h2>
                <div class="analysis-results">
                <h4>🎯 Mission Objective</h4>
                <p>รูปภาพ Happy Birthday 20th มี flag ซ่อนอยู่ใน EXIF metadata</p>
                <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                <li>ใช้ exiftool commands เพื่อวิเคราะห์ metadata</li>
                <li>ค้นหา hidden fields และ custom tags</li>
                <li>Extract flag จากข้อมูลที่ซ่อนอยู่</li>
                </ul>
                </div>
                <div style="text-align: center; margin: 2rem 0;">
                <img src="assets/images/birthday.png"
                            style="max-width: 100%; border: 2px solid var(--primary); border-radius: 10px;"
                            alt="Birthday Image">
                <p style="margin-top: 0.5rem; color: var(--gray); font-size: 0.9rem;">
                            📥 birthday.jpg (245 KB)
                </p>
                </div>
                <div class="terminal">
                <div class="terminal-output" id="exifTerminal">$ file birthday.jpg
                birthday.jpg: JPEG image data
                Available commands:
                - exiftool birthday.jpg (basic metadata)
                - exiftool -a birthday.jpg (show all tags)
                - exiftool -G birthday.jpg (show group names)
                - exiftool -Copyright birthday.jpg (specific tag)
                - strings birthday.jpg | grep -i "sec" (search strings)</div>
                <div class="terminal-input-wrapper">
                <span class="terminal-prompt">$</span>
                <input type="text" class="terminal-input" id="exifCommand"
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executeEXIFCommand()">
                </div>
                </div>
                <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('birthdayhint1')">💡 Hint 1: Basic Metadata</button>
                <div id="birthdayhint1" class="hint-content" style="display:none;">
                            Start with: exiftool birthday.jpg<br>
                            Look for unusual or custom fields<br>
                            Not all metadata is visible by default
                </div>
                <button class="hint-btn" onclick="toggleHint('birthdayhint2')">💡 Hint 2: Advanced Options</button>
                <div id="birthdayhint2" class="hint-content" style="display:none;">
                            Try: exiftool -a birthday.jpg (show ALL tags)<br>
                            Or: exiftool -Copyright birthday.jpg<br>
                            Copyright field might contain hidden data
                </div>
                <button class="hint-btn" onclick="toggleHint('birthdayhint3')">💡 Hint 3: String Search</button>
                <div id="birthdayhint3" class="hint-content" style="display:none;">
                            Use: strings birthday.jpg | grep -i "sec"<br>
                            Or check specific field: exiftool -Copyright birthday.jpg<br>
                            Flag format: secXplore{...}
                </div>
                </div>
                <div class="flag-input">
                    <input type="text" id="birthdayExifFlag" placeholder="CTF{...}">
                    <button class="submit-btn" onclick="checkFlag('birthdayExif')">Submit Flag</button>
                </div>
                <div class="success-message" id="birthdaySuccess">🎉 Correct!</div>
                <div class="error-message" id="birthdayError">❌ Incorrect flag.</div>
                `
                },
            //Forensic 2
            geoLocation: {

                content: `
                <h2 style="color: var(--primary); margin-bottom: 1rem;">🔍 Geolocation Mystery</h2>
                <div class="analysis-results">
                <h4>🎯 Mission Objective</h4>
                <p>รูปถ่ายจากตึกมี GPS coordinates ซ่อนอยู่ใน EXIF metadata</p>
                <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                <li>Extract GPS data ด้วย exiftool commands</li>
                <li>Convert coordinates และหาชื่อสถานที่</li>
                <li>Hash ชื่อสถานที่ด้วย MD5 เป็น flag</li>
                </ul>
                </div>
                <div style="text-align: center; margin: 2rem 0;">
                <img src="assets/images/Where_is_it.jpg" 

                                style="max-width: 100%; border: 2px solid var(--primary); border-radius: 10px;"

                                alt="Building View">
                <p style="margin-top: 0.5rem; color: var(--gray); font-size: 0.9rem;">

                                📥 Where_is_it.jpg (512 KB)
                </p>
                </div>
                <div class="terminal">
                <div class="terminal-output" id="geoTerminal">$ file Where_is_it.jpg

                Where_is_it.jpg: JPEG image data

                Available commands:

                - exiftool -GPS* Where_is_it.jpg (GPS data only)

                - exiftool -n -GPS* Where_is_it.jpg (numeric GPS)

                - exiftool -c "%.6f" -GPS* Where_is_it.jpg (decimal format)

                - echo -n "text" | md5sum (hash text)</div>
                <div class="terminal-input-wrapper">
                <span class="terminal-prompt">$</span>
                <input type="text" class="terminal-input" id="geoCommand" 

                                    autocomplete="off" spellcheck="false"

                                    onkeypress="if(event.key==='Enter') executeGeoCommand()">
                </div>
                </div>
                <div class="hint-box">
                <button class="hint-btn" onclick="toggleHint('geohint1')">💡 Hint 1: Extract GPS</button>
                <div id="geohint1" class="hint-content" style="display:none;">

                                Use: exiftool -GPS* Where_is_it.jpg<br>

                                Get decimal format: exiftool -n -GPS* Where_is_it.jpg<br>

                                Or: exiftool -c "%.6f" -GPS* Where_is_it.jpg
                </div>
                <button class="hint-btn" onclick="toggleHint('geohint2')">💡 Hint 2: Find Location</button>
                <div id="geohint2" class="hint-content" style="display:none;">

                                Coordinates: 13.8115, 100.5629<br>

                                Search in Google Maps: "13.8115, 100.5629"<br>

                                It's a university in Bangkok, Thailand
                </div>
                <button class="hint-btn" onclick="toggleHint('geohint3')">💡 Hint 3: Hash Location</button>
                <div id="geohint3" class="hint-content" style="display:none;">

                                Location: Bangkok University<br>

                                Command: echo -n "bangkokuniversity" | md5sum<br>

                                (lowercase, no spaces)<br>

                                Format: secXplore{md5hash}
                </div>
                </div>
                <div class="flag-input">
                <input type="text" id="geoLocationFlag" placeholder="CTF{...}">
                <button class="submit-btn" onclick="checkFlag('geoLocation')">Submit Flag</button>
                </div>
                <div class="success-message" id="geoSuccess">🎉 Correct!</div>
                <div class="error-message" id="geoError">❌ Incorrect flag.</div>

                    `

                },
            //Forensic 3
            stegoFlag: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">🔍 Steganography Battlefield</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>รูปภาพธงขาวบนกองทรายมีไฟล์ซ่อนอยู่ข้างใน (Multi-layer steganography)</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>Step 1: ใช้ binwalk หาไฟล์ที่ฝังอยู่</li>
                            <li>Step 2: Extract ZIP file ที่พบ</li>
                            <li>Step 3: Crack ZIP password</li>
                            <li>Step 4: Decode Base64 เพื่อได้ flag</li>
                        </ul>
                    </div>
                    <div style="text-align: center; margin: 2rem 0;">
                        <img src="assets/images/white_flag.png" 
                            style="max-width: 100%; border: 2px solid var(--primary); border-radius: 10px;">
                    </div>

                    <div class="terminal">
                        <div class="terminal-output" id="stegoTerminal">$ file white_flag.jpg
            white_flag.jpg: JPEG image data

            Available commands:
            - binwalk white_flag.jpg (scan for embedded files)
            - binwalk -e white_flag.jpg (extract files)
            - dd if=white_flag.jpg of=hidden.zip bs=1 skip=OFFSET (manual extract)
            - unzip -P password hidden.zip (unzip with password)
            - base64 -d file.txt (decode base64)</div>
                        <div class="terminal-input-wrapper">
                            <span class="terminal-prompt">$</span>
                            <input type="text" class="terminal-input" id="stegoCommand" 
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executeStegoCommand()">
                        </div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('stegohint1')">💡 Hint 1: Find Hidden Files</button>
                        <div id="stegohint1" class="hint-content" style="display:none;">
                            Command: binwalk white_flag.jpg<br>
                            Look for ZIP signature (PK) after JPEG end (FFD9)<br>
                            ZIP starts at offset 8187
                        </div>

                        <button class="hint-btn" onclick="toggleHint('stegohint2')">💡 Hint 2: ZIP Password</button>
                        <div id="stegohint2" class="hint-content" style="display:none;">
                            Extract: dd if=white_flag.jpg of=hidden.zip bs=1 skip=8187<br>
                            Password hint: What's in the image?<br>
                            Try: unzip -P whiteflag hidden.zip
                        </div>

                        <button class="hint-btn" onclick="toggleHint('stegohint3')">💡 Hint 3: Decode Base64</button>
                        <div id="stegohint3" class="hint-content" style="display:none;">
                            File contains: c2VjWHBsb3Jle2IxbndAbGtfc3QzZzBfYjRzZTY0X2gxZGQzbn0=<br>
                            Decode: echo "..." | base64 -d<br>
                            Or use online Base64 decoder
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="stegoFlagFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('stegoFlag')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="stegoSuccess">🎉 Correct!</div>
                    <div class="error-message" id="stegoError">❌ Incorrect flag.</div>
                `
            },
            //Forensic 4
            diskAnalysis: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">🔍 Disk Image Analysis</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>Disk image จากคอมพิวเตอร์ผู้ต้องสงสัยมีไฟล์ที่ถูกลบแล้ว ต้อง recover และวิเคราะห์</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>Step 1: Mount disk image และวิเคราะห์ filesystem</li>
                            <li>Step 2: ใช้ forensics tools หาไฟล์ที่ถูกลบ</li>
                            <li>Step 3: Recover deleted file และ analyze content</li>
                            <li>Step 4: Carve hidden data จาก slack space</li>
                            <li>Step 5: Extract flag จาก recovered data</li>
                        </ul>
                    </div>

                    <div class="analysis-results" style="margin: 2rem 0;">
                        <h4>💾 Disk Image File</h4>
                        <p style="font-family: monospace; color: var(--secondary);">
                            📥 evidence.dd (500 MB)<br>
                            Type: Raw Disk Image | Filesystem: ext4 | Deleted files: 3
                        </p>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output" id="diskTerminal">$ file evidence.dd
            evidence.dd: Linux rev 1.0 ext4 filesystem data

            Available commands:
            - mmls evidence.dd (view partition table)
            - fls -r -d evidence.dd (list deleted files)
            - icat evidence.dd [inode] (recover file by inode)
            - xxd evidence.dd | grep -i "sec" (hex dump search)
            - strings evidence.dd | grep -i "flag" (string search)
            - foremost -i evidence.dd -o output (file carving)</div>
                        <div class="terminal-input-wrapper">
                            <span class="terminal-prompt">$</span>
                            <input type="text" class="terminal-input" id="diskCommand" 
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executeDiskCommand()">
                        </div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('diskhint1')">💡 Hint 1: List Deleted Files</button>
                        <div id="diskhint1" class="hint-content" style="display:none;">
                            Use: fls -r -d evidence.dd<br>
                            Look for deleted files marked with * asterisk<br>
                            Note the inode numbers (like 12345)
                        </div>

                        <button class="hint-btn" onclick="toggleHint('diskhint2')">💡 Hint 2: Recover Files</button>
                        <div id="diskhint2" class="hint-content" style="display:none;">
                            Found deleted file: * 12847: secret_data.txt<br>
                            Recover: icat evidence.dd 12847 > recovered.txt<br>
                            View content: cat recovered.txt
                        </div>

                        <button class="hint-btn" onclick="toggleHint('diskhint3')">💡 Hint 3: File Carving</button>
                        <div id="diskhint3" class="hint-content" style="display:none;">
                            File contains partial data, use file carving<br>
                            Command: foremost -i evidence.dd -o output<br>
                            Or search hex: xxd evidence.dd | grep -A 5 "secret"<br>
                            Flag hidden in slack space at offset 0x1F4B2C
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="diskAnalysisFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('diskAnalysis')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="diskSuccess">🎉 Correct!</div>
                    <div class="error-message" id="diskError">❌ Incorrect flag.</div>
                `
            },
            //Network 1
            packetBasic: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">📡 Packet Sniffer Basic</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>วิเคราะห์ HTTP packets และหา credentials ที่ส่งแบบ plaintext</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>ใช้ tcpdump/tshark capture และวิเคราะห์ traffic</li>
                            <li>Filter HTTP POST requests</li>
                            <li>Extract username และ password จาก form data</li>
                        </ul>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output" id="packetTerminal">$ tcpdump -r capture.pcap
            Reading from capture.pcap

            Available commands:
            - tcpdump -r capture.pcap (view packets)
            - tcpdump -r capture.pcap -A (show ASCII content)
            - tshark -r capture.pcap -Y "http" (filter HTTP)
            - tshark -r capture.pcap -Y "http.request.method == POST" (POST only)
            - tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data (extract POST data)</div>
                        <div class="terminal-input-wrapper">
                            <span class="terminal-prompt">$</span>
                            <input type="text" class="terminal-input" id="packetCommand" 
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executePacketCommand()">
                        </div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('packethint1')">💡 Hint 1: Filter HTTP Traffic</button>
                        <div id="packethint1" class="hint-content" style="display:none;">
                            Command: tshark -r capture.pcap -Y "http"<br>
                            Look for POST requests to /api/login<br>
                            HTTP sends data in plaintext
                        </div>

                        <button class="hint-btn" onclick="toggleHint('packethint2')">💡 Hint 2: Extract POST Data</button>
                        <div id="packethint2" class="hint-content" style="display:none;">
                            Command: tshark -r capture.pcap -Y "http.request.method == POST"<br>
                            Or: tcpdump -r capture.pcap -A | grep "password"<br>
                            Form data format: username=...&password=...
                        </div>

                        <button class="hint-btn" onclick="toggleHint('packethint3')">💡 Hint 3: Flag Location</button>
                        <div id="packethint3" class="hint-content" style="display:none;">
                            POST /api/login contains:<br>
                            username=admin&password=secXplore{p4ck3t_sn1ff3r_pl41nt3xt}<br>
                            Flag is in password field
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="packetBasicFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('packetBasic')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="packetSuccess">🎉 Correct!</div>
                    <div class="error-message" id="packetError">❌ Incorrect flag.</div>
                `
            },
            //Network 2
            dnsTunnel: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">📡 DNS Tunneling Extract</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>Data ถูก exfiltrate ผ่าน DNS queries ให้ decode และ reconstruct ข้อมูล</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>วิเคราะห์ DNS queries ที่ผิดปกติ</li>
                            <li>Extract data จาก subdomain names</li>
                            <li>Decode และ reconstruct flag</li>
                        </ul>
                    </div>
                    <div class="terminal">
                        <div class="terminal-output" id="dnsTerminal">$ tshark -r traffic.pcap -Y "dns"
            Analyzing DNS traffic...

            Available commands:
            - tshark -r traffic.pcap -Y "dns" (filter DNS)
            - tshark -r traffic.pcap -Y "dns.qry.name" -T fields -e dns.qry.name (extract query names)
            - tshark -r traffic.pcap -Y "dns.qry.name contains exfil" (suspicious domains)
            - echo "base64string" | base64 -d (decode Base64)</div>
                        <div class="terminal-input-wrapper">
                            <span class="terminal-prompt">$</span>
                            <input type="text" class="terminal-input" id="dnsCommand" 
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executeDNSCommand()">
                        </div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('dnshint1')">💡 Hint 1: DNS Tunneling Pattern</button>
                        <div id="dnshint1" class="hint-content" style="display:none;">
                            Command: tshark -r traffic.pcap -Y "dns.qry.name contains exfil"<br>
                            Look for *.exfil.malicious.com domains<br>
                            Subdomains contain encoded data
                        </div>

                        <button class="hint-btn" onclick="toggleHint('dnshint2')">💡 Hint 2: Extract Subdomains</button>
                        <div id="dnshint2" class="hint-content" style="display:none;">
                            Found queries: NzM2NTYzNTg3MDcw.exfil.malicious.com<br>
                            C52U3MzFkNm5z.exfil.malicious.com<br>
                            Data before .exfil is Base64 encoded
                        </div>

                        <button class="hint-btn" onclick="toggleHint('dnshint3')">💡 Hint 3: Reconstruct Data</button>
                        <div id="dnshint3" class="hint-content" style="display:none;">
                            Combine all subdomains in order<br>
                            Full Base64: NzM2NTYzNTg3MDcwQzUyVTMzFkNm5zNzRfTTNoZk1sd3c3cjR0M3BufQ==<br>
                            Decode: echo "..." | base64 -d
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="dnsTunnelFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('dnsTunnel')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="dnsSuccess">🎉 Correct!</div>
                    <div class="error-message" id="dnsError">❌ Incorrect flag.</div>
                `
            },
            //Network 3
            arpSpoof: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">📡 ARP Spoofing Attack</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>จำลอง ARP spoofing attack และ intercept traffic ระหว่าง victim กับ gateway</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>ส่ง ARP replies ปลอมเพื่อ poison ARP cache</li>
                            <li>Intercept traffic ที่ผ่าน attacker machine</li>
                            <li>Extract sensitive data จาก intercepted traffic</li>
                        </ul>
                    </div>
                    <div class="terminal">
                        <div class="terminal-output" id="arpTerminal">$ arp -a
            Gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff
            Victim (192.168.1.100) at 11:22:33:44:55:66

            Available commands:
            - arp -a (view ARP table)
            - arpspoof -i eth0 -t 192.168.1.100 192.168.1.1 (poison victim)
            - tcpdump -i eth0 -n (capture traffic)
            - echo 1 > /proc/sys/net/ipv4/ip_forward (enable forwarding)</div>
                        <div class="terminal-input-wrapper">
                            <span class="terminal-prompt">$</span>
                            <input type="text" class="terminal-input" id="arpCommand" 
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executeARPCommand()">
                        </div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('arphint1')">💡 Hint 1: ARP Poisoning</button>
                        <div id="arphint1" class="hint-content" style="display:none;">
                            Command: arpspoof -i eth0 -t 192.168.1.100 192.168.1.1<br>
                            This tells victim that attacker MAC is gateway<br>
                            Need to poison both directions
                        </div>

                        <button class="hint-btn" onclick="toggleHint('arphint2')">💡 Hint 2: Enable Forwarding</button>
                        <div id="arphint2" class="hint-content" style="display:none;">
                            Command: echo 1 > /proc/sys/net/ipv4/ip_forward<br>
                            This forwards packets to real gateway<br>
                            Creates transparent MITM attack
                        </div>

                        <button class="hint-btn" onclick="toggleHint('arphint3')">💡 Hint 3: Capture Traffic</button>
                        <div id="arphint3" class="hint-content" style="display:none;">
                            Command: tcpdump -i eth0 -A | grep "password"<br>
                            Intercepted POST data contains flag<br>
                            password=secXplore{4rp_sp00f_m1tm_4tt4ck}
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="arpSpoofFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('arpSpoof')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="arpSuccess">🎉 Correct!</div>
                    <div class="error-message" id="arpError">❌ Incorrect flag.</div>
                `
            },
            //Network 4
            sslStrip: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">📡 SSL Strip Analysis</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>วิเคราะห์ HTTPS traffic ที่ถูก downgrade เป็น HTTP ด้วย SSL stripping</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>เข้าใจวิธีการทำงานของ SSL stripping attack</li>
                            <li>วิเคราะห์ traffic ที่ถูก downgrade</li>
                            <li>Extract credentials จาก stripped HTTPS connection</li>
                        </ul>
                    </div>

                    <div class="hints-section">
                        <div class="hints-warning">⚠️ Each hint costs 10 points</div>
                        <div class="hints-stats">
                            <span>Current Points: <span class="current-points">100</span></span>
                        </div>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output" id="sslTerminal">$ tshark -r stripped.pcap
            Analyzing SSL stripped traffic...

            Available commands:
            - tshark -r stripped.pcap -Y "http" (filter HTTP)
            - tshark -r stripped.pcap -Y "http.request.uri contains login" (login requests)
            - tshark -r stripped.pcap -T fields -e http.file_data (extract POST data)
            - grep -a "password" stripped.pcap (search for password)</div>
                        <div class="terminal-input-wrapper">
                            <span class="terminal-prompt">$</span>
                            <input type="text" class="terminal-input" id="sslCommand" 
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executeSSLCommand()">
                        </div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('sslhint1')">💡 Hint 1: SSL Stripping Concept</button>
                        <div id="sslhint1" class="hint-content" style="display:none;">
                            Attacker intercepts HTTPS requests<br>
                            Forwards as HTTPS to server<br>
                            Returns HTTP to victim (downgrade)<br>
                            Victim thinks using HTTP normally
                        </div>

                        <button class="hint-btn" onclick="toggleHint('sslhint2')">💡 Hint 2: Find Stripped Traffic</button>
                        <div id="sslhint2" class="hint-content" style="display:none;">
                            Command: tshark -r stripped.pcap -Y "http.request.uri contains login"<br>
                            Look for POST to http://secure-bank.com<br>
                            Should be https:// but downgraded to http://
                        </div>

                        <button class="hint-btn" onclick="toggleHint('sslhint3')">💡 Hint 3: Extract Credentials</button>
                        <div id="sslhint3" class="hint-content" style="display:none;">
                            Command: tshark -r stripped.pcap -T fields -e http.file_data<br>
                            JSON data: {"username":"admin","password":"secXplore{ssl_str1p_d0wngr4d3_pwn}"}<br>
                            Flag in password field
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="sslStripFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('sslStrip')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="sslSuccess">🎉 Correct!</div>
                    <div class="error-message" id="sslError">❌ Incorrect flag.</div>
                `
            },
            //Reversing 1
            asmPassword: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">⚙️ Assembly Password Check</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>Program ตรวจสอบ password โดยใช้ assembly code ให้วิเคราะห์ algorithm</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>อ่านและเข้าใจ assembly code</li>
                            <li>วิเคราะห์ password validation algorithm</li>
                            <li>หา password ที่ถูกต้อง</li>
                        </ul>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output">Assembly Code Analysis
        =======================

        check_password:
            push    rbp
            mov     rbp, rsp
            mov     QWORD PTR [rbp-8], rdi
            mov     rax, QWORD PTR [rbp-8]
            movzx   eax, BYTE PTR [rax]
            cmp     al, 115              ; 's'
            jne     .L2
            mov     rax, QWORD PTR [rbp-8]
            add     rax, 1
            movzx   eax, BYTE PTR [rax]
            cmp     al, 101              ; 'e'
            jne     .L2
            mov     rax, QWORD PTR [rbp-8]
            add     rax, 2
            movzx   eax, BYTE PTR [rax]
            cmp     al, 99               ; 'c'
            jne     .L2
            ; ... more comparisons ...
            mov     eax, 1
            jmp     .L3
        .L2:
            mov     eax, 0
        .L3:
            pop     rbp
            ret</div>
                    </div>

                    <div class="tool-section">
                        <h4>🔧 Assembly Analysis Tools</h4>
                        <div style="margin: 1rem 0;">
                            <input type="text" id="asmInput" placeholder="Enter password..." style="background: rgba(0,0,0,0.8); border: 1px solid var(--primary); color: var(--light); padding: 0.5rem; width: 300px; border-radius: 5px; font-family: monospace;">
                            <button class="tool-btn" onclick="testPassword()">Test Password</button>
                        </div>
                        <button class="tool-btn" onclick="analyzeASM()">Analyze Assembly</button>
                        <button class="tool-btn" onclick="showCharComparisons()">Show Character Comparisons</button>
                        <button class="tool-btn" onclick="reconstructPassword()">Reconstruct Password</button>
                        <div id="asmOutput" style="margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.8); border: 1px solid var(--secondary); border-radius: 5px; font-family: monospace; max-height: 300px; overflow-y: auto;"></div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('asmhint1')">💡 Hint 1: Assembly Basics</button>
                        <div id="asmhint1" class="hint-content">
                            คำสั่งสำคัญ:<br>
                            - cmp al, 115: เปรียบเทียบ character กับ 115 (ASCII 's')<br>
                            - jne .L2: jump ถ้าไม่เท่ากัน (password ผิด)<br>
                            - add rax, 1: ไปยัง character ถัดไป<br>
                            Code กำลังเปรียบเทียบแต่ละตัวอักษร
                        </div>

                        <button class="hint-btn" onclick="toggleHint('asmhint2')">💡 Hint 2: Character Analysis</button>
                        <div id="asmhint2" class="hint-content">
                            ASCII values ที่เปรียบเทียบ:<br>
                            Position 0: 115 = 's'<br>
                            Position 1: 101 = 'e'<br>
                            Position 2: 99 = 'c'<br>
                            ใช้ ASCII table convert ทุกค่า
                        </div>

                        <button class="hint-btn" onclick="toggleHint('asmhint3')">💡 Hint 3: Password Pattern</button>
                        <div id="asmhint3" class="hint-content">
                            Password เริ่มต้นด้วย "sec"<br>
                            ตามด้วย pattern ที่คุ้นเคย<br>
                            Format: secXplore{...}
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="asmPasswordFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('asmPassword')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="asmSuccess">🎉 Correct! You reversed the assembly code!</div>
                    <div class="error-message" id="asmError">❌ Incorrect flag. Analyze each character comparison!</div>
                `
            },
            //Reversing 2
            crackme: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">⚙️ Binary Crackme</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>Binary ที่ validate serial key ด้วย mathematical operations</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>วิเคราะห์ serial key validation algorithm</li>
                            <li>Reverse mathematical operations</li>
                            <li>Generate valid serial key</li>
                        </ul>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output">$ ./crackme
        Enter Serial Key: _

        Validation Algorithm (Pseudocode):
        ==================================
        input_key = user_input()
        checksum = 0

        for i in range(len(input_key)):
            checksum += ord(input_key[i]) * (i + 1)
            
        checksum = checksum ^ 0x1337
        checksum = (checksum * 13) % 65536

        if checksum == 0xB33F:
            print("Valid! Flag: secXplore{" + input_key + "}")
        else:
            print("Invalid serial key!")
            
        Required checksum: 0xB33F (45887)</div>
                    </div>

                    <div class="tool-section">
                        <h4>🔧 Crackme Tools</h4>
                        <div style="margin: 1rem 0;">
                            <input type="text" id="serialInput" placeholder="Enter serial key..." style="background: rgba(0,0,0,0.8); border: 1px solid var(--primary); color: var(--light); padding: 0.5rem; width: 300px; border-radius: 5px; font-family: monospace;">
                            <button class="tool-btn" onclick="validateSerial()">Validate Serial</button>
                        </div>
                        <button class="tool-btn" onclick="reverseAlgorithm()">Reverse Algorithm</button>
                        <button class="tool-btn" onclick="bruteforceSerial()">Bruteforce Serial</button>
                        <button class="tool-btn" onclick="generateSerial()">Generate Valid Serial</button>
                        <div id="crackmeOutput" style="margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.8); border: 1px solid var(--secondary); border-radius: 5px; font-family: monospace; max-height: 300px; overflow-y: auto;"></div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('crackmehint1')">💡 Hint 1: Algorithm Breakdown</button>
                        <div id="crackmehint1" class="hint-content">
                            Algorithm ทำงาน 4 ขั้นตอน:<br>
                            1. คำนวณ weighted sum ของ ASCII values<br>
                            2. XOR กับ 0x1337<br>
                            3. คูณด้วย 13 และ modulo 65536<br>
                            4. เปรียบเทียบกับ 0xB33F
                        </div>

                        <button class="hint-btn" onclick="toggleHint('crackmehint2')">💡 Hint 2: Reverse Process</button>
                        <div id="crackmehint2" class="hint-content">
                            เพื่อหา serial key ต้อง reverse:<br>
                            1. หา x ที่ (x * 13) % 65536 = 0xB33F<br>
                            2. XOR ผลลัพธ์กับ 0x1337<br>
                            3. หา string ที่ให้ weighted sum นี้<br>
                            หรือใช้ bruteforce กับ string สั้นๆ
                        </div>

                        <button class="hint-btn" onclick="toggleHint('crackmehint3')">💡 Hint 3: Serial Pattern</button>
                        <div id="crackmehint3" class="hint-content">
                            Serial key มีความยาว 6-8 characters<br>
                            ประกอบด้วย lowercase letters และตัวเลข<br>
                            ตัวอย่าง: cr4ckm3
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="crackmeFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('crackme')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="crackmeSuccess">🎉 Correct! You cracked the serial key validation!</div>
                    <div class="error-message" id="crackmeError">❌ Incorrect flag. Reverse the validation algorithm!</div>
                `
            },
            //Reversing 3
            obfuscated: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">⚙️ Obfuscated Code Analysis</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>Code ที่ถูก obfuscate ด้วย string encoding และ control flow flattening</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>De-obfuscate encoded strings</li>
                            <li>วิเคราะห์ control flow ที่ซับซ้อน</li>
                            <li>หา hidden flag ในโค้ด</li>
                        </ul>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output">Obfuscated JavaScript Code:
        ============================

        var _0x4a2b = [
            '\\x73\\x65\\x63\\x58\\x70\\x6c\\x6f\\x72\\x65',
            '\\x6f\\x62\\x66\\x75\\x73\\x63\\x34\\x74\\x33\\x64',
            '\\x63\\x30\\x64\\x33\\x5f\\x64\\x33\\x6f\\x62\\x66'
        ];

        function check(_0x1a2b3c) {
            var _0x2c4d = _0x4a2b[0x0];
            var _0x3e5f = _0x4a2b[0x1];
            var _0x4f6a = _0x4a2b[0x2];
            
            if (_0x1a2b3c === _0x2c4d + '{' + _0x3e5f + '_' + _0x4f6a + '}') {
                return true;
            }
            return false;
        }</div>
                    </div>

                    <div class="tool-section">
                        <h4>🔧 Deobfuscation Tools</h4>
                        <button class="tool-btn" onclick="decodeHexStrings()">Decode Hex Strings</button>
                        <button class="tool-btn" onclick="simplifyCode()">Simplify Code</button>
                        <button class="tool-btn" onclick="reconstructFlag()">Reconstruct Flag</button>
                        <div id="obfuscatedOutput" style="margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.8); border: 1px solid var(--secondary); border-radius: 5px; font-family: monospace; max-height: 300px; overflow-y: auto;"></div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('obfhint1')">💡 Hint 1: String Encoding</button>
                        <div id="obfhint1" class="hint-content">
                            Strings ถูก encode เป็น hex escapes:<br>
                            \\x73\\x65\\x63 = "sec"<br>
                            แต่ละ \\xNN เป็น ASCII character<br>
                            Convert hex เป็น ASCII
                        </div>

                        <button class="hint-btn" onclick="toggleHint('obfhint2')">💡 Hint 2: Array Decoding</button>
                        <div id="obfhint2" class="hint-content">
                            _0x4a2b[0x0] = first string<br>
                            _0x4a2b[0x1] = second string<br>
                            _0x4a2b[0x2] = third string<br>
                            Decode แต่ละ string แล้วรวมกัน
                        </div>

                        <button class="hint-btn" onclick="toggleHint('obfhint3')">💡 Hint 3: Flag Construction</button>
                        <div id="obfhint3" class="hint-content">
                            Flag = _0x2c4d + '{' + _0x3e5f + '_' + _0x4f6a + '}'<br>
                            แทนค่า:<br>
                            "secXplore" + "{" + "obfusc4t3d" + "_" + "c0d3_d3obf" + "}"
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="obfuscatedFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('obfuscated')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="obfuscatedSuccess">🎉 Correct! You deobfuscated the code!</div>
                    <div class="error-message" id="obfuscatedError">❌ Incorrect flag. Decode all hex strings!</div>
                `
            },
            //Reversing 4
                malwareAnalysis: {
                        content: `
                            <h2 style="color: var(--primary); margin-bottom: 1rem;">⚙️ Malware Behavior Analysis</h2>
                            
                            <div class="analysis-results">
                                <h4>🎯 Mission Objective</h4>
                                <p>วิเคราะห์ malware sample และหา C2 server address ที่ซ่อนอยู่</p>
                                <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                                    <li>วิเคราะห์ malware behavior และ network activity</li>
                                    <li>Extract encrypted C2 server address</li>
                                    <li>Decode และ reconstruct flag</li>
                                </ul>
                            </div>

                            <div class="terminal">
                                <div class="terminal-output">Malware Analysis Report
                ========================

                File: suspicious.exe
                MD5: 5d41402abc4b2a76b9719d911017c592
                SHA256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c

                Behavior Analysis:
                - Creates registry key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
                - Connects to encrypted IP address
                - Encrypts files with AES-256
                - Exfiltrates data via HTTP POST

                Encrypted C2 Server (Base64):
                MTkyLjE2OC4xLjUwOjQ0NDM=

                Additional encrypted data found in strings:
                c2VjWHBsb3Jle201bHczcjNfYzJfc2VydjNyX2YwdW5kfQ==</div>
                            </div>

                            <div class="tool-section">
                                <h4>🔧 Malware Analysis Tools</h4>
                                <button class="tool-btn" onclick="analyzeStrings()">Extract Strings</button>
                                <button class="tool-btn" onclick="decodeC2()">Decode C2 Address</button>
                                <button class="tool-btn" onclick="analyzeBehavior()">Analyze Behavior</button>
                                <button class="tool-btn" onclick="extractFlag()">Extract Flag</button>
                                <div id="malwareOutput" style="margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.8); border: 1px solid var(--secondary); border-radius: 5px; font-family: monospace; max-height: 300px; overflow-y: auto;"></div>
                            </div>

                            <div class="hint-box">
                                <button class="hint-btn" onclick="toggleHint('malwarehint1')">💡 Hint 1: C2 Communication</button>
                                <div id="malwarehint1" class="hint-content">
                                    C2 (Command & Control) server address ถูกเข้ารหัส<br>
                                    Base64 encoded: MTkyLjE2OC4xLjUwOjQ0NDM=<br>
                                    Decode เพื่อหา IP address และ port
                                </div>

                                <button class="hint-btn" onclick="toggleHint('malwarehint2')">💡 Hint 2: String Analysis</button>
                                <div id="malwarehint2" class="hint-content">
                                    ใน malware มี string ที่ encode ด้วย Base64:<br>
                                    c2VjWHBsb3Jle201bHczcjNfYzJfc2VydjNyX2YwdW5kfQ==<br>
                                    String นี้อาจเป็น flag
                                </div>

                                <button class="hint-btn" onclick="toggleHint('malwarehint3')">💡 Hint 3: Base64 Decoding</button>
                                <div id="malwarehint3" class="hint-content">
                                    Decode Base64 string:<br>
                                    c2VjWHBsb3Jle201bHczcjNfYzJfc2VydjNyX2YwdW5kfQ==<br>
                                    จะได้ flag ที่ต้องการ
                                </div>
                            </div>

                            <div class="flag-input">
                                <input type="text" id="malwareAnalysisFlag" placeholder="CTF{...}">
                                <button class="submit-btn" onclick="checkFlag('malwareAnalysis')">Submit Flag</button>
                            </div>
                            <div class="success-message" id="malwareSuccess">🎉 Correct! You analyzed the malware successfully!</div>
                            <div class="error-message" id="malwareError">❌ Incorrect flag. Decode the Base64 string!</div>
                        `
                    },
            //Moblile 1
            apkStrings: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">📱 APK String Analysis</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>Decompile APK และหา hardcoded API key ที่ซ่อนอยู่ใน strings</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>ใช้ apktool/jadx decompile APK file</li>
                            <li>วิเคราะห์ Java source code และ strings.xml</li>
                            <li>ค้นหา hardcoded secrets และ API keys</li>
                        </ul>
                    </div>
                    <div class="analysis-results" style="margin: 2rem 0;">
                        <h4>📦 APK File</h4>
                        <p style="font-family: monospace; color: var(--secondary);">
                            📥 com.secureapp.banking.apk (15.2 MB)<br>
                            Package: com.secureapp.banking | Version: 2.4.1
                        </p>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output" id="apkTerminal">$ file com.secureapp.banking.apk
            com.secureapp.banking.apk: Zip archive data, Android application package

            Available commands:
            - apktool d com.secureapp.banking.apk (decompile APK)
            - jadx -d output com.secureapp.banking.apk (decompile to Java)
            - grep -r "API_KEY" output/ (search for API keys)
            - cat output/res/values/strings.xml (view strings)
            - find output/ -name "*.java" -exec grep -l "secret" {} \; (find files with secrets)</div>
                        <div class="terminal-input-wrapper">
                            <span class="terminal-prompt">$</span>
                            <input type="text" class="terminal-input" id="apkCommand" 
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executeAPKCommand()">
                        </div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('apkhint1')">💡 Hint 1: Decompile APK</button>
                        <div id="apkhint1" class="hint-content" style="display:none;">
                            Use: jadx -d output com.secureapp.banking.apk<br>
                            This extracts Java source code<br>
                            Look in output/sources/com/secureapp/banking/
                        </div>

                        <button class="hint-btn" onclick="toggleHint('apkhint2')">💡 Hint 2: Search for Keys</button>
                        <div id="apkhint2" class="hint-content" style="display:none;">
                            Command: grep -r "API_KEY" output/<br>
                            Or: cat output/sources/com/secureapp/banking/Constants.java<br>
                            API keys often in Constants or Config files
                        </div>

                        <button class="hint-btn" onclick="toggleHint('apkhint3')">💡 Hint 3: Decode Base64</button>
                        <div id="apkhint3" class="hint-content" style="display:none;">
                            Found: API_KEY = "c2VjWHBsb3Jle2gwcmRjMGQzZF9hcGlfa2V5X2YwdW5kfQ=="<br>
                            Decode: echo "..." | base64 -d<br>
                            Flag format: secXplore{...}
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="apkAnalysisFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('apkAnalysis')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="apkSuccess">🎉 Correct!</div>
                    <div class="error-message" id="apkError">❌ Incorrect flag.</div>
                `
            },
            //Mobile 2
            rootBypass: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">📱 Root Detection Bypass</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>App ตรวจสอบ root ด้วยหลายวิธี ให้หาทางข้ามการตรวจสอบ</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>วิเคราะห์ root detection methods</li>
                            <li>Patch APK หรือใช้ Frida hook</li>
                            <li>เข้าถึง hidden feature ที่ต้องการ non-root device</li>
                        </ul>
                    </div>

                    <div class="hints-section">
                        <div class="hints-warning">⚠️ Each hint costs 10 points</div>
                        <div class="hints-stats">
                            <span>Current Points: <span class="current-points">100</span></span>
                        </div>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output" id="rootTerminal">$ jadx -d output com.secureapp.apk
            Decompiling...

            Available commands:
            - cat output/sources/.../MainActivity.java (view code)
            - grep -r "isRooted" output/ (find root checks)
            - apktool d com.secureapp.apk (decompile to smali)
            - frida -U -f com.secureapp -l bypass.js (hook with Frida)
            - adb shell "su -c 'which su'" (check for su binary)</div>
                        <div class="terminal-input-wrapper">
                            <span class="terminal-prompt">$</span>
                            <input type="text" class="terminal-input" id="rootCommand" 
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executeRootCommand()">
                        </div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('roothint1')">💡 Hint 1: Find Root Checks</button>
                        <div id="roothint1" class="hint-content" style="display:none;">
                            Command: grep -r "isRooted" output/<br>
                            Found in: MainActivity.java<br>
                            Method checks for: su binary, test-keys, root apps
                        </div>

                        <button class="hint-btn" onclick="toggleHint('roothint2')">💡 Hint 2: Frida Hook</button>
                        <div id="roothint2" class="hint-content" style="display:none;">
                            Create bypass.js with hook for isRooted()<br>
                            Command: frida -U -f com.secureapp -l bypass.js<br>
                            Hook returns false to bypass checks
                        </div>

                        <button class="hint-btn" onclick="toggleHint('roothint3')">💡 Hint 3: Access Hidden Feature</button>
                        <div id="roothint3" class="hint-content" style="display:none;">
                            After bypass, Admin Panel button appears<br>
                            Click to reveal flag<br>
                            Flag: secXplore{r00t_d3t3ct_byp4ss3d}
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="rootDetectionFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('rootDetection')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="rootSuccess">🎉 Correct!</div>
                    <div class="error-message" id="rootError">❌ Incorrect flag.</div>
                `
            },
            //Mobile 3
            sslPinning: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">📱 SSL Pinning Challenge</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>App ใช้ certificate pinning ให้ bypass และ intercept HTTPS traffic</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>เข้าใจ SSL/TLS certificate pinning</li>
                            <li>Bypass pinning ด้วย Frida หรือ objection</li>
                            <li>Intercept HTTPS traffic ด้วย Burp Suite</li>
                        </ul>
                    </div>
                    <div class="terminal">
                        <div class="terminal-output" id="sslPinTerminal">$ grep -r "CertificatePinner" output/
            Found SSL pinning implementation in NetworkModule.java

            Available commands:
            - cat output/sources/.../NetworkModule.java (view pinning code)
            - frida -U -f com.app -l ssl-bypass.js (bypass SSL pinning)
            - objection -g com.app explore (interactive bypass)
            - adb shell "settings put global http_proxy 192.168.1.100:8080" (set proxy)</div>
                        <div class="terminal-input-wrapper">
                            <span class="terminal-prompt">$</span>
                            <input type="text" class="terminal-input" id="sslPinCommand" 
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executeSSLPinCommand()">
                        </div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('sslpinhint1')">💡 Hint 1: Analyze Pinning</button>
                        <div id="sslpinhint1" class="hint-content" style="display:none;">
                            Command: cat output/sources/.../NetworkModule.java<br>
                            Uses OkHttp3 CertificatePinner<br>
                            Pins certificate for api.secureapp.com
                        </div>

                        <button class="hint-btn" onclick="toggleHint('sslpinhint2')">💡 Hint 2: Frida Bypass</button>
                        <div id="sslpinhint2" class="hint-content" style="display:none;">
                            Command: frida -U -f com.app -l ssl-bypass.js<br>
                            Hook CertificatePinner.check() to return void<br>
                            All certificates now accepted
                        </div>

                        <button class="hint-btn" onclick="toggleHint('sslpinhint3')">💡 Hint 3: Intercept Traffic</button>
                        <div id="sslpinhint3" class="hint-content" style="display:none;">
                            Setup Burp: adb shell settings put global http_proxy 127.0.0.1:8080<br>
                            POST /v1/auth contains device_id field<br>
                            Flag: secXplore{ssl_p1nn1ng_byp4ss3d}
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="sslPinningFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('sslPinning')">Submit Flag</button>
                    </div>
                    <div class="success-message" id="sslPinSuccess">🎉 Correct!</div>
                    <div class="error-message" id="sslPinError">❌ Incorrect flag.</div>
                `
            },
            //Mobile 4
            nativeLib: {
                content: `
                    <h2 style="color: var(--primary); margin-bottom: 1rem;">📱 Native Library Reverse</h2>
                    
                    <div class="analysis-results">
                        <h4>🎯 Mission Objective</h4>
                        <p>Reverse engineer native SO library ที่มี encryption function</p>
                        <ul style="margin: 0.5rem 0; padding-left: 2rem;">
                            <li>Extract .so library จาก APK</li>
                            <li>Analyze ARM assembly code</li>
                            <li>Reverse encryption algorithm และ extract flag</li>
                        </ul>
                    </div>

                    <div class="terminal">
                        <div class="terminal-output" id="nativeTerminal">$ unzip -l com.app.apk | grep ".so"
            1234567  lib/armeabi-v7a/libnative-lib.so
            2345678  lib/arm64-v8a/libnative-lib.so

            Available commands:
            - unzip com.app.apk lib/armeabi-v7a/libnative-lib.so (extract SO)
            - file libnative-lib.so (check file type)
            - objdump -d libnative-lib.so (disassemble)
            - strings libnative-lib.so | grep -i "flag" (search strings)
            - readelf -s libnative-lib.so (view symbols)</div>
                        <div class="terminal-input-wrapper">
                            <span class="terminal-prompt">$</span>
                            <input type="text" class="terminal-input" id="nativeCommand" 
                                autocomplete="off" spellcheck="false"
                                onkeypress="if(event.key==='Enter') executeNativeCommand()">
                        </div>
                    </div>

                    <div class="hint-box">
                        <button class="hint-btn" onclick="toggleHint('nativehint1')">💡 Hint 1: Disassemble SO</button>
                        <div id="nativehint1" class="hint-content" style="display:none;">
                            Command: objdump -d libnative-lib.so<br>
                            Find encrypt function at offset 0x1234<br>
                            Uses XOR 0x42 and ADD 0x10
                        </div>

                        <button class="hint-btn" onclick="toggleHint('nativehint2')">💡 Hint 2: Reverse Algorithm</button>
                        <div id="nativehint2" class="hint-content" style="display:none;">
                            Encryption: byte = (input ^ 0x42) + 0x10<br>
                            Decryption: byte = (encrypted - 0x10) ^ 0x42<br>
                            Found encrypted string in strings
                        </div>

                        <button class="hint-btn" onclick="toggleHint('nativehint3')">💡 Hint 3: Decrypt Flag</button>
                        <div id="nativehint3" class="hint-content" style="display:none;">
                            Encrypted: 93A7C3BFA3B793CBA3B793CFB3AF93BF93CFB3CF93B793C7<br>
                            Python: chr(((0x93 - 0x10) ^ 0x42)) for each byte<br>
                            Result: secXplore{n4t1v3_l1b_r3v3rs3d}
                        </div>
                    </div>

                    <div class="flag-input">
                        <input type="text" id="nativeLibFlag" placeholder="CTF{...}">
                        <button class="submit-btn" onclick="checkFlag('nativeLib')">Submit Flag</button>
                    </div>
                    <div class="error-message" id="nativeError">❌ Incorrect flag.</div>
                `
            }
        
    };

// ============================================
// 5. HELPER FUNCTIONS & SIMULATION LOGIC
// ============================================

// --- UI Helpers ---
function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    setTimeout(() => notification.classList.add('show'), 10);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function showError(element, message) {
    if (element) {
        element.style.display = 'block';
        element.textContent = message;
        setTimeout(() => element.style.display = 'none', 3000);
    }
}

function updatePointsDisplay() {
    if (currentUser) {
        // Update elements in interactive modals
        const points = document.querySelectorAll('.current-points');
        points.forEach(el => el.textContent = currentUser.score);
    }
}

function createParticles() {
    const particlesContainer = document.getElementById('particles');
    if (!particlesContainer) return;
    particlesContainer.innerHTML = '';
    for (let i = 0; i < 100; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 15 + 's';
        particle.style.animationDuration = (Math.random() * 10 + 10) + 's';
        particlesContainer.appendChild(particle);
    }
}

// --- Confirmation Dialog Logic ---
function showHintConfirmation(hintId, pointDeduction, onConfirm) {
    const confirmDialog = document.createElement('div');
    confirmDialog.className = 'confirm-overlay';
    const hintNumber = hintId.match(/hint(\d+)$/)?.[1] || '?';
    
    confirmDialog.innerHTML = `
        <div class="confirm-dialog">
            <h3>⚠️ ยืนยันการใช้ Hint ${hintNumber}</h3>
            <p>การเปิด hint นี้จะหัก <strong style="color: var(--danger);">${pointDeduction} คะแนน</strong></p>
            <div class="confirm-buttons">
                <button class="btn-cancel" onclick="closeHintConfirmDialog()">ยกเลิก</button>
                <button class="btn-confirm" onclick="confirmHint()">ยืนยัน</button>
            </div>
        </div>
    `;
    document.body.appendChild(confirmDialog);
    window.hintConfirmCallback = onConfirm;
    setTimeout(() => confirmDialog.classList.add('show'), 10);
}

function closeHintConfirmDialog() {
    const dialog = document.querySelector('.confirm-overlay');
    if (dialog) {
        dialog.classList.remove('show');
        setTimeout(() => dialog.remove(), 300);
    }
    delete window.hintConfirmCallback;
}

window.confirmHint = function() {
    if (window.hintConfirmCallback) window.hintConfirmCallback();
    closeHintConfirmDialog();
};

// ============================================
// 6. SIMULATION LOGIC (Client-side visuals only)
// ============================================

// SQL Simulation
let sqlAttemptCount = 0;
window.attemptSQLLogin = function() {
    sqlAttemptCount++;
    const user = document.getElementById('sqlUser').value;
    const query = `SELECT * FROM users WHERE username='${user}'`;
    const debug = document.getElementById('sqlDebug');
    const result = document.getElementById('sqlResult');
    
    debug.innerHTML = `<div style="margin-bottom:1rem;"><strong>Query:</strong><br><code>${query}</code></div>`;
    
    // Client-side visual check only (Real check happens in checkFlag)
    if (user.toLowerCase().includes("' or '1'='1")) {
        result.innerHTML = `✅ Login Successful! Flag: <code style="color:var(--success)">secXplore{sql_1nj3ct10n_byp4ss_adm1n}</code>`;
        result.style.background = 'rgba(0,255,136,0.1)';
    } else {
        result.innerHTML = `❌ Login Failed`;
        result.style.background = 'rgba(255,0,102,0.1)';
    }
};

// CMD Simulation
window.executeCMD = function() {
    const input = document.getElementById('cmdInput').value;
    const result = document.getElementById('cmdResult');
    
    if (input.includes(';')) {
        if (input.includes('cat') && input.includes('flag')) {
            result.innerHTML = `<pre style="color:var(--success)">PING 127.0.0.1...\n\nsecXplore{c0mm4nd_1nj3ct10n_pwn3d}</pre>`;
        } else {
            result.innerHTML = `<pre>PING 127.0.0.1...\n\nfiles:\nindex.php\nflag.txt</pre>`;
        }
    } else {
        result.innerHTML = `<pre>PING ${input}...\n64 bytes from ${input}: icmp_seq=1 ttl=64 time=0.04ms</pre>`;
    }
};

// XOR Simulation
window.xorDecrypt = function() {
    const keyHex = document.getElementById('xorKey').value;
    // ... logic เดิม ...
    document.getElementById('xorOutput').innerHTML = `Trying key 0x${keyHex}...`;
};
window.xorBruteForce = function() {
    // ... logic เดิม ...
    document.getElementById('xorOutput').innerHTML = `Brute forcing... Found readable text with Key 0x79`;
};

// ============================================
// 7. NAVIGATION & MODAL EXPORTS
// ============================================

// เรียกจากหน้า challenge.html
window.openChallengeList = function(category) {
    // 1. กรองโจทย์ตามหมวดหมู่
    const catChallenges = dbChallenges.filter(c => c.category === category);
    
    const modal = document.getElementById('challengeModal');
    const list = document.getElementById('challengeList');
    const modalTitle = document.getElementById('modalTitle');
    const progressText = document.getElementById('progressText');
    const progressFill = document.getElementById('progressFill');
    
    // 2. ตั้งชื่อหัวข้อ
    // Map ชื่อหมวดให้สวยงาม (Optional)
    const categoryNames = {
        web: '🌐 Web Security',
        crypto: '🔐 Cryptography',
        forensics: '🔍 Digital Forensics',
        network: '📡 Network Security',
        reverse: '⚙️ Reverse Engineering',
        mobile: '📱 Mobile Security'
    };
    modalTitle.textContent = categoryNames[category] || category.toUpperCase();
    
    // 3. คำนวณ Progress (ส่วนที่เพิ่มเข้ามา)
    const total = catChallenges.length;
    // นับจำนวนข้อที่ทำเสร็จแล้ว (เช็คจาก userProgressDB)
    const solvedCount = catChallenges.filter(c => userProgressDB[c.challenge_id]).length;
    const percent = total > 0 ? Math.round((solvedCount / total) * 100) : 0;

    // อัปเดต UI Progress Bar
    if (progressText && progressFill) {
        progressText.textContent = `${solvedCount} of ${total} completed (${percent}%)`;
        progressFill.style.width = `${percent}%`;
    }

    // 4. สร้างรายการโจทย์ (List)
    list.innerHTML = '';
    if (catChallenges.length === 0) {
        list.innerHTML = '<p style="text-align:center; padding:2rem; color:#888;">No challenges available in this category.</p>';
    }

    catChallenges.forEach(c => {
        // Map DB Code to Short ID for UI logic (e.g. 'WEB001' -> 'sql')
        // ในที่นี้ผมจะ Reverse Lookup จาก Mapping หรือคุณอาจเพิ่ม column short_id ใน DB ก็ได้
        const shortId = Object.keys(ID_MAPPING).find(key => ID_MAPPING[key] === c.title);
        
        const isSolved = userProgressDB[c.challenge_id];
        const statusClass = isSolved ? 'completed' : '';
        const statusBadge = isSolved ? '<div class="status-badge status-completed">COMPLETE</div>' : '<div class="status-badge status-not-started">START</div>';

        const item = document.createElement('div');
        item.className = `challenge-item ${statusClass}`;
        item.innerHTML = `
            <div class="challenge-header">
                <div class="challenge-name">${c.title}</div>
                <div class="challenge-right">
                    ${statusBadge}
                    <div class="challenge-points">${c.score_base} pts</div>
                </div>
            </div>
            <div class="challenge-description">${c.description}</div>
            <div class="challenge-meta">
                <span class="difficulty-badge difficulty-${c.difficulty}">${c.difficulty}</span>
            </div>
        `;
        
        // Add Click Event
        if (shortId && interactiveChallenges[shortId]) {
            item.onclick = () => openInteractiveChallenge(shortId);
        } else {
            item.onclick = () => alert('UI for this challenge is under construction.');
        }
        
        list.appendChild(item);
    });

    modal.classList.add('active');
};

window.closeModal = function() {
    document.getElementById('challengeModal').classList.remove('active');
};

window.confirmBackToCategory = function() {
    document.getElementById('interactiveModal').classList.remove('active');
};