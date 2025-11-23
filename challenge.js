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
                            <li>Flag จะอยู่ในรูปแบบ CTF{...}</li>
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
                            Flag เริ่มต้นด้วย "CTF{"<br>
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
                <img src="1_Hbd_20th.png"
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
                            Flag format: CTF{...}
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
                <img src="2_Where_is_it.jpg" 

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

                                Format: CTF{md5hash}
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
                        <img src="3_flag_img.png" 
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
                            username=admin&password=CTF{p4ck3..}<br>
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
// 6. INTERACTIVE CHALLENGE LOGIC (from challenge1.js)
// ============================================

// Web Security - SQL Injection

let sqlAttemptCount = 0;
const MAX_SQL_ATTEMPTS = 10;

window.attemptSQLLogin = function() {
    if (sqlAttemptCount >= MAX_SQL_ATTEMPTS) {
        showSQLResult('danger', '❌ Maximum attempts reached! Refresh to try again.');
        return;
    }
    
    sqlAttemptCount++;
    document.getElementById('sqlAttempts').textContent = sqlAttemptCount;
    
    const user = document.getElementById('sqlUser').value;
    const pass = document.getElementById('sqlPass').value;
    const resultPanel = document.getElementById('sqlResult');
    const debugPanel = document.getElementById('sqlDebug');
    
    if (!user || !pass) {
        showSQLResult('warning', '⚠️ Please enter both username and password');
        updateDebug('No input provided', '');
        return;
    }
    
    // Build the SQL query (for display)
    const query = `SELECT * FROM users WHERE username='${user}' AND password='${pass}'`;
    
    // Check for blocked patterns (case-sensitive)
    const blockedPatterns = ['OR', 'AND', '--', '/*'];
    let blocked = false;
    let blockedPattern = '';
    
    for (let pattern of blockedPatterns) {
        if (user.includes(pattern) || pass.includes(pattern)) {
            blocked = true;
            blockedPattern = pattern;
            break;
        }
    }
    
    if (blocked) {
        showSQLResult('danger', `❌ Security Filter Triggered!<br>Blocked pattern detected: <code>${blockedPattern}</code><br>Try to bypass the filter...`);
        updateDebug(query, 'BLOCKED');
        return;
    }
    
    // Check for successful injection patterns
    const successPatterns = [
        /admin'.*or.*'1'='1'/i,
        /admin'.*\|\|.*1=1/i,
        /admin'.*or.*1=1/i,
        /admin'.*union/i
    ];
    
    let successful = false;
    for (let pattern of successPatterns) {
        if (user.toLowerCase().match(pattern)) {
            // Check if it uses comment to close the query
            if (user.includes('#') || user.includes(';')) {
                successful = true;
                break;
            }
        }
    }
    
    if (successful) {
        showSQLResult('success', `✅ Authentication Successful!<br><br>
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(0,255,136,0.1); border-radius: 8px;">
                <strong>Access Level: ADMINISTRATOR</strong><br>
                User ID: 1<br>
                Username: admin<br>
                Role: superadmin<br><br>
                🎉 Flag: <code style="color: var(--success); font-size: 1.1rem;">CTF{sql_1nj3ct10n_byp4ss}</code>
            </div>`);
        updateDebug(query, 'SUCCESS', 'Query returned 1 row(s)<br>Admin access granted!');
    } else if (user.includes("'")) {
        showSQLResult('warning', `⚠️ SQL Syntax Error<br>Your injection attempt caused a syntax error.<br>Check the debug panel for details.`);
        updateDebug(query, 'SYNTAX ERROR', 'Unclosed quote or invalid syntax');
    } else {
        showSQLResult('danger', `❌ Login Failed<br>Invalid credentials<br><small>Hint: There's a SQL injection vulnerability here...</small>`);
        updateDebug(query, 'FAILED', 'Query returned 0 row(s)');
    }
}

function showSQLResult(type, message) {
    const resultPanel = document.getElementById('sqlResult');
    const colors = {
        success: 'rgba(0, 255, 136, 0.2)',
        danger: 'rgba(255, 0, 102, 0.2)',
        warning: 'rgba(255, 170, 0, 0.2)'
    };
    const borderColors = {
        success: 'var(--success)',
        danger: 'var(--danger)',
        warning: 'var(--warning)'
    };
    
    resultPanel.style.background = colors[type];
    resultPanel.style.border = `2px solid ${borderColors[type]}`;
    resultPanel.innerHTML = message;
    
    // Animate
    resultPanel.style.animation = 'none';
    setTimeout(() => {
        resultPanel.style.animation = 'slideIn 0.3s ease';
    }, 10);
}

function updateDebug(query, status, details = '') {
    const debugPanel = document.getElementById('sqlDebug');
    const statusColors = {
        'SUCCESS': 'var(--success)',
        'FAILED': 'var(--danger)',
        'BLOCKED': 'var(--warning)',
        'SYNTAX ERROR': 'var(--danger)'
    };
    
    debugPanel.innerHTML = `
        <div style="margin-bottom: 1rem;">
            <strong style="color: var(--secondary);">Query Executed:</strong><br>
            <code style="color: var(--light); word-break: break-all;">${query}</code>
        </div>
        <div style="margin-bottom: 1rem;">
            <strong style="color: var(--secondary);">Status:</strong> 
            <span style="color: ${statusColors[status] || 'var(--light)'};">${status}</span>
        </div>
        ${details ? `<div><strong style="color: var(--secondary);">Details:</strong><br>${details}</div>` : ''}
    `;
}
// Web Security - Command Injection
window.executeCMD = function() {
    const input = document.getElementById('cmdInput').value;
    const result = document.getElementById('cmdResult');
    
    if (!input) {
        result.innerHTML = `<span style="color: var(--warning);">⚠️ Please enter a target IP</span>`;
        return;
    }

    if (input.includes(';') || input.includes('&&') || input.includes('||') || input.includes('|')) {
        const parts = input.split(/[;&|]+/);
        const commands = parts.slice(1).join(' ').toLowerCase();
        
        if (commands.includes('ls') || commands.includes('dir')) {
            result.innerHTML = `<span style="color: var(--light);">Pinging ${parts[0]}...
PING ${parts[0]} (${parts[0]}) 56(84) bytes of data.
64 bytes from ${parts[0]}: icmp_seq=1 ttl=64 time=0.042 ms

--- ${parts[0]} ping statistics ---
1 packets transmitted, 1 received, 0% packet loss

Executing: ${commands}
Files found:
index.php
config.php
uploads/
.htaccess
flag.txt

Hint: Try reading flag.txt with 'cat' command!</span>`;
        } else if (commands.includes('cat') && commands.includes('flag')) {
            result.innerHTML = `<span style="color: var(--success);">Pinging ${parts[0]}...
PING ${parts[0]} (${parts[0]}) 56(84) bytes of data.
64 bytes from ${parts[0]}: icmp_seq=1 ttl=64 time=0.038 ms

Executing: ${commands}

✅ Content of flag.txt:
CTF{c0mm4nd_1nj3ct10n_pwn3d}

Copy the flag and submit below!</span>`;
        } else {
            result.innerHTML = `<span style="color: var(--secondary);">Pinging ${parts[0]}...
PING ${parts[0]} (${parts[0]}) 56(84) bytes of data.
64 bytes from ${parts[0]}: icmp_seq=1 ttl=64 time=0.045 ms

Executing: ${commands}
Command executed but no relevant output.</span>`;
        }
    } else {
        result.innerHTML = `<span style="color: var(--light);">Pinging ${input}...
PING ${input} (${input}) 56(84) bytes of data.
64 bytes from ${input}: icmp_seq=1 ttl=64 time=0.042 ms

--- ${input} ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.042/0.042/0.042/0.000 ms</span>`;
    }
}

// Web Security - XSS Cookie Stealer
window.submitXSS = function() {
    const input = document.getElementById('xssInput').value;
    const result = document.getElementById('xssResult');
    const preview = document.getElementById('xssPreview');
    
    if (!input) {
        result.innerHTML = `<span style="color: var(--warning);">⚠️ Please enter a comment</span>`;
        return;
    }

    if (input.toLowerCase().includes('<script') || input.toLowerCase().includes('onerror') || input.toLowerCase().includes('onclick')) {
        result.innerHTML = `<span style="color: var(--danger);">❌ XSS Filter: Blocked dangerous patterns</span>`;
        preview.innerHTML = '';
        return;
    }

    if (input.includes('<svg') || input.includes('<img') || input.includes('<iframe') || input.includes('onload')) {
        result.innerHTML = `<span style="color: var(--success);">✅ Comment Posted Successfully!

XSS Payload Executed!
Admin Cookie Stolen: admin_session=CTF{xss_c00k13_st34l3r}

Copy the flag and submit below!</span>`;
        preview.innerHTML = `<div style="color: var(--success);">Comment Preview: ${input.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>`;
    } else {
        result.innerHTML = `<span style="color: var(--secondary);">Comment posted but no XSS triggered. Try different payloads!</span>`;
        preview.innerHTML = `<div>Comment Preview: ${input.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>`;
    }
}
// Web Security - JWT Token Manipulation
window.verifyJWT = function() {
    const token = document.getElementById('jwtInput').value.trim();
    const result = document.getElementById('jwtResult');
    
    if (!token) {
        result.innerHTML = `<span style="color: var(--warning);">⚠️ Please enter a JWT token</span>`;
        return;
    }

    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            result.innerHTML = `<span style="color: var(--danger);">❌ Invalid JWT format</span>`;
            return;
        }

        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));

        if (header.alg === 'HS256' && payload.role === 'admin') {
            result.innerHTML = `<span style="color: var(--success);">✅ Token Verified Successfully!

Access Level: ADMIN
Algorithm: HS256
Flag: CTF{jwt_alg0r1thm_c0nfus10n}

You successfully exploited the algorithm confusion vulnerability!</span>`;
        } else if (payload.role === 'admin') {
            result.innerHTML = `<span style="color: var(--warning);">⚠️ Role is admin but wrong algorithm. Try HS256!</span>`;
        } else {
            result.innerHTML = `<span style="color: var(--danger);">❌ Access Denied: Insufficient privileges</span>`;
        }
    } catch (e) {
        result.innerHTML = `<span style="color: var(--danger);">❌ Token decoding error</span>`;
    }
}

window.decodeJWT = function() {
    document.getElementById('toolOutput').innerHTML = `Original Token Decoded:
Header: {"alg":"RS256","typ":"JWT"}
Payload: {"user":"user","role":"user","iat":1633024800}

To become admin, change "role":"user" to "role":"admin"`;
}

window.showPublicKey = function() {
    document.getElementById('toolOutput').innerHTML = `Public Key (PEM):
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----

Hint: Use this as HMAC secret for HS256!`;
}

window.createHS256 = function() {
    document.getElementById('toolOutput').innerHTML = `Sample HS256 Token with admin role:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYzMzAyNDgwMH0.signature

Try pasting this in the verify box!`;
}

// Cryptography - Multi-Layer Cipher
window.decodeROT13 = function() {
    const input = document.getElementById('cipherInput').value || 'FrpKcyber{p3e4_y4l3e_qrpelcg_z4fgre}';
    const decoded = input.replace(/[a-zA-Z]/g, c => 
        String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)
    );
    document.getElementById('cipherOutput').innerHTML = `ROT13 Result: ${decoded}`;
}

window.decodeBase64Cipher = function() {
    const input = document.getElementById('cipherInput').value;
    if (!input) {
        document.getElementById('cipherOutput').innerHTML = 'Please enter text to decode';
        return;
    }
    try {
        const decoded = atob(input);
        document.getElementById('cipherOutput').innerHTML = `Base64 Result: ${decoded}`;
    } catch (e) {
        document.getElementById('cipherOutput').innerHTML = 'Invalid Base64 string';
    }
}

window.decodeCaesar = function() {
    const input = document.getElementById('cipherInput').value || 'CTF{mult1_l4y3r_c1ph3r}';
    const decoded = input.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base - 3 + 26) % 26) + base);
    });
    document.getElementById('cipherOutput').innerHTML = `Caesar (shift -3) Result: ${decoded}`;
}

window.decodeAll = function() {
    const input = 'FrpKcyber{p3e4_y4l3e_qrpelcg_z4fgre}';
    let step1 = input.replace(/[a-zA-Z]/g, c => 
        String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)
    );
    let step3 = step1.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base - 3 + 26) % 26) + base);
    });
    document.getElementById('cipherOutput').innerHTML = `Step 1 (ROT13): ${step1}
Step 2 (No Base64 needed): ${step1}
Step 3 (Caesar -3): ${step3}

Final Answer: ${step3}`;
}

// Cryptography - XOR Brute Force

window.xorDecrypt = function() {
    const keyHex = document.getElementById('xorKey').value;
    if (!keyHex || keyHex.length !== 2) {
        document.getElementById('xorOutput').innerHTML = 'Please enter a 2-digit hex key (00-FF)';
        return;
    }
    const key = parseInt(keyHex, 16);
    const encrypted = '1c060b59121b0d1612461a5d4c1a0d465b0e0b1a5d454c0d';
    let decrypted = '';
    for (let i = 0; i < encrypted.length; i += 2) {
        const byte = parseInt(encrypted.substr(i, 2), 16);
        decrypted += String.fromCharCode(byte ^ key);
    }
    document.getElementById('xorOutput').innerHTML = `Key 0x${keyHex}: ${decrypted}`;
}

window.xorBruteForce = function() {
    const encrypted = '1c060b59121b0d1612461a5d4c1a0d465b0e0b1a5d454c0d';
    let output = 'Brute Force Results:\n\n';
    for (let key = 0; key < 256; key++) {
        let decrypted = '';
        for (let i = 0; i < encrypted.length; i += 2) {
            const byte = parseInt(encrypted.substr(i, 2), 16);
            decrypted += String.fromCharCode(byte ^ key);
        }
        if (decrypted.includes('secXplore') || /^[a-zA-Z{}_0-9]+$/.test(decrypted)) {
            output += `Key 0x${key.toString(16).padStart(2, '0')}: ${decrypted}\n`;
        }
    }
    document.getElementById('xorOutput').innerHTML = output || 'No readable results found. Try key 0x79';
}

// Cryptography - RSA Small Exponent Attack

window.calculateCRT = function() {
    document.getElementById('rsaOutput').innerHTML = `Calculating Chinese Remainder Theorem...

Given:
c1 ≡ m³ (mod n1)
c2 ≡ m³ (mod n2)
c3 ≡ m³ (mod n3)

Using CRT to find m³ mod (n1*n2*n3)
Result: m³ = 7067388259113537318333

Next: Calculate cube root`;
}

window.calculateCubeRoot = function() {
    document.getElementById('rsaOutput').innerHTML = `Calculating cube root of m³...

m³ = 7067388259113537318333
m = ∛(m³) = 1919252867

Converting to bytes...
Result: CTF{rs4_sm4ll_3xp0n3nt}`;
}

window.convertToText = function() {
    document.getElementById('rsaOutput').innerHTML = `Converting number to text...

1919252867 → bytes → ASCII
Result: CTF{rs4_sm4ll_3xp0n3nt}

Flag found!`;
}

// Cryptography - Custom Cipher Analysis
window.decryptCustom = function() {
    const key = document.getElementById('customKey').value;
    const ciphertext = document.getElementById('customCiphertext').value;
    
    let plaintext = '';
    for (let i = 0; i < ciphertext.length; i++) {
        const char = ciphertext[i];
        if (/[a-zA-Z]/.test(char)) {
            const shift = (key.charCodeAt(i % key.length) + i) % 26;
            const base = char <= 'Z' ? 65 : 97;
            plaintext += String.fromCharCode(((char.charCodeAt(0) - base - shift + 26) % 26) + base);
        } else {
            plaintext += char;
        }
    }
    
    document.getElementById('customOutput').innerHTML = `Decrypted: ${plaintext}`;
}

window.analyzeCustom = function() {
    document.getElementById('customOutput').innerHTML = `Algorithm Analysis:
==================
Type: Modified Vigenere Cipher
Key: "CTF" (repeating)
Position-dependent shift: (key[i % len] + i) % 26

To decrypt:
plaintext[i] = (ciphertext[i] - shift) % 26`;
}

// Forensics - Birthday EXIF Data
window.executeEXIFCommand = function() {
    const input = document.getElementById('exifCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('exifTerminal');
    if (!command) return;
    
    // แสดงคำสั่งที่พิมพ์
    terminal.innerHTML += `\n$ ${command}`;
    const cmd = command.toLowerCase();
    
    // exiftool with -a flag (all tags)
    if (cmd.includes('exiftool') && cmd.includes('birthday') && cmd.includes('-a')) {
        terminal.innerHTML += `
ExifTool Version Number         : 12.40
File Name                       : birthday.jpg
File Size                       : 245 KB
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Image Width                     : 1200
Image Height                    : 800
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Camera Model Name               : Canon EOS 5D
Date/Time Original              : 2024:01:20 14:30:00
Create Date                     : 2024:01:20 14:30:00
Artist                          : Anonymous
Copyright                       : secXplore
User Comment                    : Happy 20th Birthday!
Software                        : Adobe Photoshop CS6
Color Space                     : sRGB
Exif Image Width                : 1200
Exif Image Height               : 800
GPS Position                    : (not set)`;
    }
    // exiftool with -Copyright flag
    else if (cmd.includes('exiftool') && cmd.includes('-copyright')) {
        terminal.innerHTML += `
Copyright                       : secXplore`;
    }
    // exiftool with -G flag (group names)
    else if (cmd.includes('exiftool') && cmd.includes('birthday') && cmd.includes('-g')) {
        terminal.innerHTML += `
[File]          File Name                       : birthday.jpg
[File]          File Size                       : 245 KB
[File]          File Type                       : JPEG
[EXIF]          Camera Model Name               : Canon EOS 5D
[EXIF]          Date/Time Original              : 2024:01:20 14:30:00
[EXIF]          Artist                          : Anonymous
[IFD0]          Copyright                       : CTF{ex1f_h1dd3n_m3ss4g3}
[EXIF]          User Comment                    : Happy 20th Birthday!`;
    }
    // basic exiftool
    else if (cmd.includes('exiftool') && cmd.includes('birthday')) {
        terminal.innerHTML += `
File Name                       : birthday.jpg
File Size                       : 245 KB
File Type                       : JPEG
Image Width                     : 1200
Image Height                    : 800
Camera Model Name               : Canon EOS 5D
Date/Time Original              : 2024:01:20 14:30:00
Artist                          : Anonymous
Try: exiftool -a birthday.jpg for all tags`;
    }
    // strings command
    else if (cmd.includes('strings') && cmd.includes('birthday')) {
        if (cmd.includes('grep') && cmd.includes('sec')) {
            terminal.innerHTML += `
Searching for 'sec' pattern...
CTF{ex1f_h1dd3n_m3ss4g3}`;
        } else {
            terminal.innerHTML += `
JFIF
Adobe
Photoshop
Canon
EOS 5D
Anonymous
Happy 20th Birthday!
CTF{ex1f_h1dd3n_m3ss4g3}
sRGB
...`;
        }
    }
    // file command
    else if (cmd === 'file birthday.jpg') {
        terminal.innerHTML += `
birthday.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 1200x800, components 3`;
    }
    // ls command
    else if (cmd === 'ls' || cmd === 'ls -la') {
        terminal.innerHTML += `
total 245
-rw-r--r-- 1 user user 245KB Jan 20 14:30 birthday.jpg`;
    }
    // help
    else if (cmd === 'help') {
        terminal.innerHTML += `
Available commands:
- exiftool birthday.jpg
- exiftool -a birthday.jpg (show all tags)
- exiftool -G birthday.jpg (with group names)
- exiftool -Copyright birthday.jpg (specific field)
- strings birthday.jpg | grep -i "sec"
- file birthday.jpg
- ls`;
    }
    // clear
    else if (cmd === 'clear') {
        terminal.innerHTML = `$ file birthday.jpg
birthday.jpg: JPEG image data
Available commands:
- exiftool birthday.jpg (basic metadata)
- exiftool -a birthday.jpg (show all tags)
- exiftool -G birthday.jpg (show group names)
- exiftool -Copyright birthday.jpg (specific tag)
- strings birthday.jpg | grep -i "sec" (search strings)`;
        input.value = '';
        return;
    }
    // command not found
    else {
        terminal.innerHTML += `
bash: ${command}: command not found
Type 'help' for available commands`;
    }
    
    // Clear input and scroll
    input.value = '';
    const terminalContainer = terminal.closest('.terminal');
    terminalContainer.scrollTop = terminalContainer.scrollHeight;
    input.focus();
}
// Forensics - Geolocation Tracker

window.executeGeoCommand = function() {
    const input = document.getElementById('geoCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('geoTerminal');
    if (!command) return;
    
    terminal.innerHTML += `\n$ ${command}`;
    const cmd = command.toLowerCase();
    
    // exiftool with GPS and numeric format
    if (cmd.includes('exiftool') && cmd.includes('gps') && (cmd.includes('-n') || cmd.includes('%.6f'))) {
        terminal.innerHTML += `
GPS Latitude                    : 13.8115
GPS Longitude                   : 100.5629
GPS Altitude                    : 45 m Above Sea Level
GPS Latitude Ref                : North
GPS Longitude Ref               : East
GPS Altitude Ref                : Above Sea Level
GPS Time Stamp                  : 07:30:00
GPS Date Stamp                  : 2024:01:20`;
    }
    // exiftool with GPS (DMS format)
    else if (cmd.includes('exiftool') && cmd.includes('gps')) {
        terminal.innerHTML += `
GPS Latitude                    : 13 deg 48' 41.40" N
GPS Longitude                   : 100 deg 33' 46.44" E
GPS Altitude                    : 45 m Above Sea Level
GPS Time Stamp                  : 07:30:00
GPS Date Stamp                  : 2024:01:20
GPS Position                    : 13 deg 48' 41.40" N, 100 deg 33' 46.44" E
Use -n flag for decimal format: exiftool -n -GPS* Where_is_it.jpg`;
    }
    // basic exiftool
    else if (cmd.includes('exiftool') && cmd.includes('where')) {
        terminal.innerHTML += `
File Name                       : Where_is_it.jpg
File Size                       : 512 KB
Camera Model                    : iPhone 12
Date/Time Original              : 2024:01:20 14:30:00
GPS Position                    : 13 deg 48' 41.40" N, 100 deg 33' 46.44" E
Try: exiftool -GPS* Where_is_it.jpg for GPS data only`;
    }
    // md5sum with correct answer
    else if (cmd.includes('md5') && cmd.includes('bangkokuniversity')) {
        terminal.innerHTML += `
4a8d8c8e8f3b5d7c9e2a1f6b4c8d3e9a  -`;
    }
    // md5sum general
    else if (cmd.includes('echo') && cmd.includes('md5')) {
        if (cmd.includes('bangkok') && !cmd.includes('bangkokuniversity')) {
            terminal.innerHTML += `
Wrong format. Try: echo -n "bangkokuniversity" | md5sum
(lowercase, no spaces)`;
        } else {
            terminal.innerHTML += `
Usage: echo -n "text" | md5sum
Example: echo -n "bangkokuniversity" | md5sum`;
        }
    }
    // file command
    else if (cmd.includes('file') && cmd.includes('where')) {
        terminal.innerHTML += `
Where_is_it.jpg: JPEG image data, EXIF standard 2.2, resolution (DPI), density 72x72`;
    }
    // help
    else if (cmd === 'help') {
        terminal.innerHTML += `
Available commands:
- exiftool Where_is_it.jpg
- exiftool -GPS* Where_is_it.jpg (GPS only)
- exiftool -n -GPS* Where_is_it.jpg (decimal)
- echo -n "text" | md5sum
- file Where_is_it.jpg
- ls`;
    }
    // clear
    else if (cmd === 'clear') {
        terminal.innerHTML = `$ file Where_is_it.jpg
Where_is_it.jpg: JPEG image data
Available commands:
- exiftool -GPS* Where_is_it.jpg (GPS data only)
- exiftool -n -GPS* Where_is_it.jpg (numeric GPS)
- exiftool -c "%.6f" -GPS* Where_is_it.jpg (decimal format)
- echo -n "text" | md5sum (hash text)`;
        input.value = '';
        return;
    }
    // ls
    else if (cmd === 'ls' || cmd === 'ls -la') {
        terminal.innerHTML += `
total 512
-rw-r--r-- 1 user user 512KB Jan 20 14:30 Where_is_it.jpg`;
    }
    // command not found
    else {
        terminal.innerHTML += `
bash: ${command}: command not found
Type 'help' for available commands`;
    }
    
    input.value = '';
    const terminalContainer = terminal.closest('.terminal');
    terminalContainer.scrollTop = terminalContainer.scrollHeight;
    input.focus();
}

// Steganography
window.executeStegoCommand = function() {
    const input = document.getElementById('stegoCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('stegoTerminal');
    
    if (!command) return;
    
    // แสดงคำสั่งที่พิมพ์พร้อม prompt
    terminal.innerHTML += `\n$ ${command}`;
    
    const cmd = command.toLowerCase();
    
    if (cmd.includes('binwalk') && !cmd.includes('-e')) {
        terminal.innerHTML += `
DECIMAL   HEXADECIMAL  DESCRIPTION
--------------------------------------------------------------------------------
0         0x0          JPEG image data, JFIF standard 1.01
8185      0x1FF9       End of JPEG (FF D9)
8187      0x1FFB       Zip archive data, encrypted
8534      0x2156       End of Zip archive

Found ZIP file at offset 8187!`;
    } 
    else if (cmd.includes('binwalk -e') || cmd.includes('dd')) {
        terminal.innerHTML += `
Extracting hidden.zip...
347 bytes extracted
File: hidden.zip (password protected)`;
    } 
    else if (cmd.includes('unzip')) {
        if (cmd.includes('whiteflag')) {
            terminal.innerHTML += `
Archive: hidden.zip
inflating: secret.txt

Contents of secret.txt:
c2VjWHBsb3Jle2IxbndAbGtfc3QzZzBfYjRzZTY0X2gxZGQzbn0=`;
        } else {
            terminal.innerHTML += `
Archive: hidden.zip
Error: incorrect password
Hint: Look at the image content`;
        }
    } 
    else if (cmd.includes('base64 -d') || cmd.includes('base64 --decode')) {
        terminal.innerHTML += `
CTF{st3g4n0gr4phy_m4st3r}`;
    } 
    else {
        terminal.innerHTML += `
bash: ${command}: command not found
Try: binwalk white_flag.jpg`;
    }
    
    // Clear input
    input.value = '';
    
    // Scroll to bottom
    const terminalContainer = terminal.closest('.terminal');
    terminalContainer.scrollTop = terminalContainer.scrollHeight;
    
    // Focus back to input
    input.focus();
}
// Disk Analysis

window.executeDiskCommand = function() {
    const input = document.getElementById('diskCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('diskTerminal');
    
    if (!command) return;
    
    terminal.innerHTML += `\n$ ${command}`;
    
    const cmd = command.toLowerCase();
    
    // mmls - view partition table
    if (cmd.includes('mmls')) {
        terminal.innerHTML += `
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

    Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0001026047   0001024000   Linux (0x83)
003:  -------   0001026048   0001048575   0000022528   Unallocated

Partition 002 contains ext4 filesystem`;
    }
    // fls - list files including deleted
    else if (cmd.includes('fls') && cmd.includes('-d')) {
        terminal.innerHTML += `
r/r 11: lost+found
d/d 12: home
r/r 15: .bash_history
r/r 16: Documents
* r/r 12847: secret_data.txt (deleted)
r/r 17: Pictures
r/r 18: Downloads
* r/r 12848: important.pdf (deleted)
* r/r 12849: .hidden_file (deleted)
r/r 19: Desktop

Found 3 deleted files!
Note inode 12847 for secret_data.txt`;
    }
    // fls without -d (only active files)
    else if (cmd.includes('fls') && !cmd.includes('-d')) {
        terminal.innerHTML += `
r/r 11: lost+found
d/d 12: home
r/r 15: .bash_history
r/r 16: Documents
r/r 17: Pictures
r/r 18: Downloads
r/r 19: Desktop

No deleted files shown. Use -d flag to show deleted files`;
    }
    // icat - recover file by inode (wrong inode)
    else if (cmd.includes('icat') && !cmd.includes('12847')) {
        terminal.innerHTML += `
Error: Cannot recover file from inode
File may be too fragmented or overwritten
Try inode 12847 for secret_data.txt`;
    }
    // icat - recover correct file
    else if (cmd.includes('icat') && cmd.includes('12847')) {
        if (cmd.includes('>') || cmd.includes('cat')) {
            terminal.innerHTML += `
File recovered successfully!

Content of secret_data.txt:
============================
Project: SecretOps
Date: 2024-01-15
Status: CONFIDENTIAL

Notes:
- Meeting at 3 PM
- Password changed to: [CORRUPTED]
- Flag location: Check slack space at offset 0x1F4B2C
- [DATA CORRUPTED - USE FILE CARVING]

File appears corrupted. Try file carving or hex search`;
        } else {
            terminal.innerHTML += `
QnJvamVjdDogU2VjcmV0T3BzCkRhdGU6IDIwMjQtMDEtMTUKU3RhdHVz...
(binary data - redirect to file: icat evidence.dd 12847 > recovered.txt)`;
        }
    }
    // strings search for flag
    else if (cmd.includes('strings') && cmd.includes('flag')) {
        terminal.innerHTML += `
Searching for "flag" in strings...

/home/user/.bash_history
rm secret_data.txt
shred -u important.pdf
Flag location: slack space
Project SecretOps
Meeting notes
[PARTIAL] CTF{d1sk_4n4ly
[CORRUPTED DATA]

Partial flag found! Need to search deeper`;
    }
    // strings search for sec
    else if (cmd.includes('strings') && cmd.includes('sec')) {
        terminal.innerHTML += `
secret_data.txt
SecretOps
CTF{d1sk_4n4lys1s_pr0}
/home/user/.secret
Security clearance

Full flag found in strings!`;
    }
    // xxd hex dump with grep
    else if (cmd.includes('xxd') && cmd.includes('grep')) {
        if (cmd.includes('sec') || cmd.includes('flag')) {
            terminal.innerHTML += `
001f4b20: 6461 7461 2073 6563 5870 6c6f 7265 7b64  data CTF{d1}
001f4b30: 3173 6b5f 6630 7233 6e73 3163 735f 6433  1sk_f0r3ns1cs_d3
001f4b40: 6c33 7433 645f 7233 6330 7633 7279 7d00  l3t3d_r3c0v3ry}.

Flag found at offset 0x1F4B2C!
CTF{d1sk_4n4lys1s_pr0}`;
        } else {
            terminal.innerHTML += `
00000000: 5375 7065 7220 626c 6f63 6b20 6261 636b  Super block back
00000010: 7570 2073 746f 7265 6420 6174 2062 6c6f  up stored at blo
Try: xxd evidence.dd | grep -i "sec"`;
        }
    }
    // foremost file carving
    else if (cmd.includes('foremost')) {
        terminal.innerHTML += `
Foremost version 1.5.7 by Jesse Kornblum, Kris Kendall, and Nick Mikus
Processing: evidence.dd
|*************************************************|

Extracting files...
jpg:= 3
png:= 2
txt:= 5
pdf:= 1

Output written to: output/
Check output/txt/00000847.txt for recovered data

File 00000847.txt contains:
CTF{d1sk_4n4lys1s_pr0}`;
    }
    // fsstat - filesystem statistics
    else if (cmd.includes('fsstat')) {
        terminal.innerHTML += `
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name: evidence
Volume ID: 1a2b3c4d5e6f7890

METADATA INFORMATION
--------------------------------------------
Inode Range: 11 - 12849
Root Directory: 2
Free Inodes: 134217728

First Data Block: 0
Block Size: 4096
Fragment Size: 4096
Blocks Per Group: 32768
Total Block Groups: 15

Deleted inodes available for recovery`;
    }
    // dd to extract specific offset
    else if (cmd.includes('dd') && cmd.includes('skip') && cmd.includes('0x1f4b2c')) {
        terminal.innerHTML += `
32+0 records in
32+0 records out
32 bytes copied

Extracted data:
CTF{d1sk_4n4lys1s_pr0}`;
    }
    // dd wrong offset
    else if (cmd.includes('dd') && cmd.includes('skip')) {
        terminal.innerHTML += `
Extracted data contains no useful information
Try offset 0x1F4B2C (decimal: 2050860)`;
    }
    // help
    else if (cmd === 'help') {
        terminal.innerHTML += `
Available commands:
- mmls evidence.dd (partition table)
- fls -r -d evidence.dd (list deleted files)
- icat evidence.dd [inode] (recover file)
- strings evidence.dd | grep -i "pattern"
- xxd evidence.dd | grep -i "pattern"
- foremost -i evidence.dd -o output
- fsstat evidence.dd (filesystem stats)
- dd if=evidence.dd bs=1 skip=OFFSET count=100`;
    }
    // clear
    else if (cmd === 'clear') {
        terminal.innerHTML = `$ file evidence.dd
evidence.dd: Linux rev 1.0 ext4 filesystem data

Available commands:
- mmls evidence.dd (view partition table)
- fls -r -d evidence.dd (list deleted files)
- icat evidence.dd [inode] (recover file by inode)
- xxd evidence.dd | grep -i "sec" (hex dump search)
- strings evidence.dd | grep -i "flag" (string search)
- foremost -i evidence.dd -o output (file carving)`;
        input.value = '';
        return;
    }
    // command not found
    else {
        terminal.innerHTML += `
bash: ${command}: command not found
Type 'help' for available commands`;
    }
    
    input.value = '';
    const terminalContainer = terminal.closest('.terminal');
    terminalContainer.scrollTop = terminalContainer.scrollHeight;
    input.focus();
}
// Network
window.executePacketCommand = function() {
    const input = document.getElementById('packetCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('packetTerminal');
            
    if (!command) return;
            
    terminal.innerHTML += `\n$ ${command}`;
            
    const cmd = command.toLowerCase();
            
    if (cmd.includes('tcpdump -r') && !cmd.includes('-a')) {
        terminal.innerHTML += `
14:23:01.123456 IP 192.168.1.105.52341 > 10.0.0.50.80: Flags [S], seq 1234567890
14:23:01.124567 IP 10.0.0.50.80 > 192.168.1.105.52341: Flags [S.], seq 9876543210
14:23:01.234567 IP 192.168.1.105.52341 > 10.0.0.50.80: Flags [P.], POST /api/login

Too many packets. Use tshark -Y "http" to filter`;
    }
    else if (cmd.includes('tcpdump') && cmd.includes('-a')) {
        terminal.innerHTML += `
POST /api/login HTTP/1.1
Host: insecure-bank.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=CTF{p4ck3t_sn1ff3r_b4s1c}&remember=true

Found plaintext credentials!`;
    }
    else if (cmd.includes('tshark') && cmd.includes('http') && !cmd.includes('post')) {
        terminal.innerHTML += `
147   14.523456 192.168.1.105 → 10.0.0.50    HTTP GET /index.html
289   29.123456 192.168.1.105 → 10.0.0.50    HTTP GET /api/data
432   43.654321 192.168.1.105 → 10.0.0.50    HTTP POST /api/login

Use -Y "http.request.method == POST" to filter POST only`;
    }
    else if (cmd.includes('tshark') && cmd.includes('post')) {
        if (cmd.includes('-t fields')) {
            terminal.innerHTML += `
username=admin&password=CTF{p4ck3t_sn1ff3r_b4s1c}&remember=true

Flag found in POST data!`;
        } else {
            terminal.innerHTML += `
432   43.654321 192.168.1.105 → 10.0.0.50    HTTP POST /api/login
        
Frame 432: HTTP POST /api/login
    Content-Type: application/x-www-form-urlencoded
    Form data: username=admin&password=CTF{p4ck3t_sn1ff3r_b4s1c}

    Add -T fields -e http.file_data to extract data`;
            }
        }
        else if (cmd === 'help') {
            terminal.innerHTML += `
    Available commands:
    - tcpdump -r capture.pcap
    - tcpdump -r capture.pcap -A
    - tshark -r capture.pcap -Y "http"
    - tshark -r capture.pcap -Y "http.request.method == POST"`;
        }
        else if (cmd === 'clear') {
            terminal.innerHTML = `$ tcpdump -r capture.pcap
    Reading from capture.pcap

    Available commands:
    - tcpdump -r capture.pcap (view packets)
    - tcpdump -r capture.pcap -A (show ASCII content)
    - tshark -r capture.pcap -Y "http" (filter HTTP)
    - tshark -r capture.pcap -Y "http.request.method == POST" (POST only)
    - tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data (extract POST data)`;
            input.value = '';
            return;
        }
        else {
            terminal.innerHTML += `
    bash: ${command}: command not found`;
        }
            
        input.value = '';
        const terminalContainer = terminal.closest('.terminal');
        terminalContainer.scrollTop = terminalContainer.scrollHeight;
        input.focus();
}
// DNS Tunneling Command Executor
function executeDNSCommand() {
    const input = document.getElementById('dnsCommand');
    const command = input.value.trim();
    const terminal = document.getElementById('dnsTerminal');
            
    if (!command) return;
            
    terminal.innerHTML += `\n$ ${command}`;
            
    const cmd = command.toLowerCase();
            
    if (cmd.includes('tshark') && cmd.includes('dns') && !cmd.includes('exfil') && !cmd.includes('-t fields')) {
        terminal.innerHTML += `
    3   0.002222 192.168.1.105 → 8.8.8.8      DNS Standard query A google.com
    4   0.003333 8.8.8.8 → 192.168.1.105      DNS Standard query response
15   1.234567 192.168.1.105 → 8.8.8.8      DNS Standard query A NzM2NTYz.exfil.malicious.com
28   2.345678 192.168.1.105 → 8.8.8.8      DNS Standard query A NTg3MDcw.exfil.malicious.com

Suspicious DNS queries detected! Use filter with "exfil"`;
    }
    else if (cmd.includes('tshark') && cmd.includes('exfil') && cmd.includes('-t fields')) {
        terminal.innerHTML += `
NzM2NTYzNTg3MDcw.exfil.malicious.com
QzUyVTM.exfil.malicious.com
zFkNm5z.exfil.malicious.com
NzRfTTN.exfil.malicious.com
oZk1sd3c.exfil.malicious.com
3cjR0M3.exfil.malicious.com
BufQ==.exfil.malicious.com

DNS tunneling detected! Combine subdomains and decode Base64`;
    }
    else if (cmd.includes('tshark') && cmd.includes('exfil') && !cmd.includes('-t fields')) {
        terminal.innerHTML += `
15   1.234567 192.168.1.105 → 8.8.8.8      DNS A NzM2NTYzNTg3MDcw.exfil.malicious.com
28   2.345678 192.168.1.105 → 8.8.8.8      DNS A QzUyVTM.exfil.malicious.com
31   2.456789 192.168.1.105 → 8.8.8.8      DNS A zFkNm5z.exfil.malicious.com

Add -T fields -e dns.qry.name to extract query names only`;
    }
    else if (cmd.includes('echo') && cmd.includes('base64 -d')) {
        if (cmd.includes('NzM2NTYzNTg3MDcwQzUyVTMzFkNm5zNzRfTTNoZk1sd3c3cjR0M3BufQ==')) {
            terminal.innerHTML += `
CTF{dns_tunn31_3xtr4ct}`;
        } else {
            terminal.innerHTML += `
Combine all subdomains first, then decode`;
        }
    }
    else if (cmd === 'help') {
        terminal.innerHTML += `
Available commands:
- tshark -r traffic.pcap -Y "dns"
- tshark -r traffic.pcap -Y "dns.qry.name contains exfil"
- tshark -r traffic.pcap -Y "dns.qry.name" -T fields -e dns.qry.name
- echo "base64" | base64 -d`;
    }
    else if (cmd === 'clear') {
        terminal.innerHTML = `$ tshark -r traffic.pcap -Y "dns"
Analyzing DNS traffic...

Available commands:
- tshark -r traffic.pcap -Y "dns" (filter DNS)
- tshark -r traffic.pcap -Y "dns.qry.name" -T fields -e dns.qry.name (extract query names)
- tshark -r traffic.pcap -Y "dns.qry.name contains exfil" (suspicious domains)
- echo "base64string" | base64 -d (decode Base64)`;
        input.value = '';
        return;
    }
    else {
        terminal.innerHTML += `
bash: ${command}: command not found`;
    }
            
    input.value = '';
    const terminalContainer = terminal.closest('.terminal');
    terminalContainer.scrollTop = terminalContainer.scrollHeight;
    input.focus();
}

// ============================================
// 7. NAVIGATION & MODAL EXPORTS
// ============================================

// เรียกจากหน้า challenge.html
window.openChallengeList = function(category) {
    // 1. กรองโจทย์ตามหมวดหมู่ และเรียงตามคะแนน (น้อยไปมาก)
    const catChallenges = dbChallenges
        .filter(c => c.category === category)
        .sort((a, b) => a.score_base - b.score_base); // <--- เพิ่มบรรทัดนี้
    
    const modal = document.getElementById('challengeModal');
    const list = document.getElementById('challengeList');
    const modalTitle = document.getElementById('modalTitle');
    const progressText = document.getElementById('progressText');
    const progressFill = document.getElementById('progressFill');
    
    // 2. ตั้งชื่อหัวข้อ
    const categoryNames = {
        web: '🌐 Web Security',
        crypto: '🔐 Cryptography',
        forensics: '🔍 Digital Forensics',
        network: '📡 Network Security',
        reverse: '⚙️ Reverse Engineering',
        mobile: '📱 Mobile Security'
    };
    modalTitle.textContent = categoryNames[category] || category.toUpperCase();
    
    // 3. คำนวณ Progress
    const total = catChallenges.length;
    const solvedCount = catChallenges.filter(c => userProgressDB[c.challenge_id]).length;
    const percent = total > 0 ? Math.round((solvedCount / total) * 100) : 0;

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
        const shortId = Object.keys(ID_MAPPING).find(key => ID_MAPPING[key] === c.title);
        const isSolved = userProgressDB[c.challenge_id];
        
        const statusBadge = isSolved 
            ? '<div class="status-badge status-completed">COMPLETE</div>' 
            : '<div class="status-badge status-not-started">START</div>';
            
        const item = document.createElement('div');
        item.className = `challenge-item ${isSolved ? 'completed' : ''}`;
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
        
        // Logic การเปิด Modal
        if (shortId && interactiveChallenges[shortId]) {
            item.onclick = () => openInteractiveChallenge(shortId);
        } else if (c.interactive_id && interactiveChallenges[c.interactive_id]) {
            item.onclick = () => openInteractiveChallenge(c.interactive_id);
        } else {
            item.onclick = () => alert(`Challenge UI not ready for: ${c.title}`);
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

