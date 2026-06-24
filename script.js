const passwordInput = document.getElementById('password-input');
const toggleBtn = document.getElementById('toggle-visibility');
const toggleIcon = toggleBtn.querySelector('i');
const generateBtn = document.getElementById('generate-btn');
const exportBtn = document.getElementById('export-btn');
const lengthSlider = document.getElementById('length-slider');
const lengthVal = document.getElementById('length-val');
const genUpper = document.getElementById('gen-upper');
const genNumbers = document.getElementById('gen-numbers');
const genSymbols = document.getElementById('gen-symbols');
const scoreValue = document.getElementById('score-value');
const entropyValue = document.getElementById('entropy-value');
const timeValue = document.getElementById('time-value');
const breachAlert = document.getElementById('breach-alert');
const historyAlert = document.getElementById('history-alert');

const checkItems = {
    upper: document.getElementById('check-upper'),
    lower: document.getElementById('check-lower'),
    numbers: document.getElementById('check-numbers'),
    symbols: document.getElementById('check-symbols'),
    length: document.getElementById('check-length')
};

const charSets = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+~`|}{[]:;?><,./-='
};

let localHistory = JSON.parse(localStorage.getItem('securepass_history') || '[]');
let saveTimeout;

toggleBtn.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    toggleIcon.className = isPassword ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
    toggleIcon.style.color = isPassword ? '#00f3ff' : '#888';
});

lengthSlider.addEventListener('input', (e) => {
    lengthVal.textContent = e.target.value;
});

generateBtn.addEventListener('click', () => {
    let charset = charSets.lower;
    if (genUpper.checked) charset += charSets.upper;
    if (genNumbers.checked) charset += charSets.numbers;
    if (genSymbols.checked) charset += charSets.symbols;

    let newPassword = '';
    const length = parseInt(lengthSlider.value);
    const array = new Uint32Array(length);
    window.crypto.getRandomValues(array);
    
    for (let i = 0; i < length; i++) {
        newPassword += charset[array[i] % charset.length];
    }

    passwordInput.value = newPassword;
    analyzePassword(newPassword);
    saveToHistory(newPassword);
});

passwordInput.addEventListener('input', (e) => {
    const pwd = e.target.value;
    analyzePassword(pwd);
    
    clearTimeout(saveTimeout);
    if (pwd.length >= 6) {
        saveTimeout = setTimeout(() => {
            saveToHistory(pwd);
        }, 2000);
    }
});

exportBtn.addEventListener('click', () => {
    const pwd = passwordInput.value;
    if (!pwd) return;
    
    const reportData = `SecurePass Analyzer Report\n` +
                       `==========================\n` +
                       `Date: ${new Date().toLocaleString()}\n` +
                       `Length: ${pwd.length} characters\n` +
                       `Security Score: ${scoreValue.textContent}/100\n` +
                       `Entropy: ${entropyValue.textContent}\n` +
                       `Estimated Crack Time: ${timeValue.textContent}\n\n` +
                       `Security Checks:\n` +
                       `- Uppercase: ${/[A-Z]/.test(pwd) ? 'Pass' : 'Fail'}\n` +
                       `- Lowercase: ${/[a-z]/.test(pwd) ? 'Pass' : 'Fail'}\n` +
                       `- Numbers: ${/[0-9]/.test(pwd) ? 'Pass' : 'Fail'}\n` +
                       `- Symbols: ${/[^A-Za-z0-9]/.test(pwd) ? 'Pass' : 'Fail'}\n` +
                       `- Length > 12: ${pwd.length > 12 ? 'Pass' : 'Fail'}\n`;

    const blob = new Blob([reportData], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'SecurePass_Report.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
});

function analyzePassword(password) {
    if (!password) {
        resetUI();
        return;
    }

    exportBtn.style.display = 'flex';

    const checks = {
        lower: /[a-z]/.test(password),
        upper: /[A-Z]/.test(password),
        numbers: /[0-9]/.test(password),
        symbols: /[^A-Za-z0-9]/.test(password),
        length: password.length > 12
    };

    updateCheckUI(checks);

    let poolSize = 0;
    if (checks.lower) poolSize += 26;
    if (checks.upper) poolSize += 26;
    if (checks.numbers) poolSize += 10;
    if (checks.symbols) poolSize += 32;

    const entropy = poolSize === 0 ? 0 : password.length * Math.log2(poolSize);
    entropyValue.textContent = `${Math.round(entropy)} bits`;

    const guesses = Math.pow(poolSize, password.length);
    const guessesPerSecond = 10000000000;
    const seconds = guesses / guessesPerSecond;
    timeValue.textContent = formatTime(seconds);

    const score = calculateScore(checks, entropy, password.length);
    updateScoreUI(score);

    if (localHistory.includes(password)) {
        historyAlert.style.display = 'flex';
    } else {
        historyAlert.style.display = 'none';
    }

    if (score < 40 || (password.length > 0 && password.length < 8) || isCommonPassword(password)) {
        breachAlert.style.display = 'flex';
    } else {
        breachAlert.style.display = 'none';
    }
}

function saveToHistory(password) {
    if (!password || password.length < 6) return;
    if (!localHistory.includes(password)) {
        localHistory.push(password);
        if (localHistory.length > 100) localHistory.shift();
        localStorage.setItem('securepass_history', JSON.stringify(localHistory));
    }
}

function updateCheckUI(checks) {
    for (const [key, element] of Object.entries(checkItems)) {
        const icon = element.querySelector('i');
        if (checks[key]) {
            element.classList.add('valid');
            icon.className = 'fa-solid fa-check';
        } else {
            element.classList.remove('valid');
            icon.className = 'fa-solid fa-xmark';
        }
    }
}

function calculateScore(checks, entropy, length) {
    let score = 0;
    if (checks.lower) score += 10;
    if (checks.upper) score += 15;
    if (checks.numbers) score += 15;
    if (checks.symbols) score += 20;
    
    if (length >= 8) score += 10;
    if (length > 12) score += 15;
    
    if (entropy > 60) score += 15;
    else if (entropy > 40) score += 5;

    return Math.min(100, score);
}

function updateScoreUI(score) {
    scoreValue.textContent = score;
    const scoreDisplay = document.querySelector('.score-display');
    
    if (score < 40) {
        scoreDisplay.style.color = '#ff3366';
    } else if (score < 70) {
        scoreDisplay.style.color = '#ffaa00';
    } else if (score < 90) {
        scoreDisplay.style.color = '#00f3ff';
    } else {
        scoreDisplay.style.color = '#00ff88';
    }
}

function isCommonPassword(pwd) {
    const common = ['123456', 'password', '12345678', 'qwerty', '123456789'];
    return common.includes(pwd.toLowerCase());
}

function formatTime(seconds) {
    if (!isFinite(seconds) || seconds > 1e12) return '1M+ Years';
    if (seconds < 1) return 'Instant';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)}d`;
    return `${Math.round(seconds / 31536000)}y`;
}

function resetUI() {
    scoreValue.textContent = '0';
    entropyValue.textContent = '0 bits';
    timeValue.textContent = '0s';
    breachAlert.style.display = 'none';
    historyAlert.style.display = 'none';
    exportBtn.style.display = 'none';
    document.querySelector('.score-display').style.color = '#00ff88';
    
    for (const element of Object.values(checkItems)) {
        element.classList.remove('valid');
        element.querySelector('i').className = 'fa-solid fa-xmark';
    }
}