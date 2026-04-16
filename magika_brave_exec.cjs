/**
 * magika_brave_exec.cjs
 * =====================
 * Brave LV3 + Magika + OpenClaw exec 聯動示範
 * 
 * 用法:
 *   node magika_brave_exec.cjs "python script.py"
 *   node magika_brave_exec.cjs "python script.py" --auto
 */

const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const https = require('https');

// ─── 1. File Extraction ─────────────────────────────────────

const SCRIPT_EXTS = 'py|js|ts|ps1|sh|rb|php|java|go|rs|cpp|c|h';

function extractFilePaths(command) {
    const found = new Set();
    
    // Quoted paths
    const quoted = command.match(/['"]([^'"]+)['"]/g) || [];
    for (const m of quoted) found.add(m.slice(1, -1));
    
    // Unquoted script paths (simple word+ext pattern)
    const re = new RegExp(`([^\\s'"]+\\.(${SCRIPT_EXTS}))`, 'gi');
    let m;
    while ((m = re.exec(command)) !== null) found.add(m[1]);
    
    // Resolve relative to cwd and filter existing
    const cwd = process.cwd();
    return [...found].map(p => {
        // Convert to absolute path if relative
        if (!path.isAbsolute(p)) {
            p = path.join(cwd, p);
        }
        return p;
    }).filter(p => {
        try { return fs.existsSync(p); } 
        catch { return false; }
    });
}

// ─── 2. Magika Scan ────────────────────────────────────────

const SCANNER = path.join(__dirname, 'magika_exec_scanner.py');

function magikaScan(command) {
    return new Promise((resolve) => {
        const proc = spawn('python', [SCANNER, command], {
            shell: true,
            windowsHide: true
        });
        
        let stdout = '';
        
        proc.stdout.on('data', d => stdout += d);
        proc.stderr.on('data', d => stdout += d);
        
        proc.on('close', () => {
            const scans = [];
            const output = stdout;
            
            // Check for BLOCK in output first
            const isBlocked = output.includes('[BLOCK]');
            
            // Parse file entries: "  filename\n    Extension: ...\n    Predicted: ...\n    Score: ..."
            // Match lines that start with spaces followed by filename with extension
            const fileRegex = /^\s+([\w./\\\-]+\.\w+)\s*$/gm;
            let match;
            
            while ((match = fileRegex.exec(output)) !== null) {
                const filename = match[1];
                const blockStart = match.index;
                const blockText = output.substring(blockStart, blockStart + 300);
                
                let predicted = 'unknown';
                let score = 0;
                let label = 'unknown';
                
                const predMatch = blockText.match(/Predicted:\s*(.+)/);
                if (predMatch) predicted = predMatch[1].trim();
                
                const scoreMatch = blockText.match(/Score:\s*([\d.]+)/);
                if (scoreMatch) score = parseFloat(scoreMatch[1]);
                
                if (isBlocked) label = 'BLOCK';
                else if (output.includes('[ALLOW]')) label = 'ALLOW';
                else if (output.includes('[WARN]')) label = 'WARN';
                
                scans.push({ file: filename, predicted, score, label });
            }
            
            resolve(scans);
        });
        
        proc.on('error', () => resolve([]));
        
        setTimeout(() => resolve([]), 15000);
    });
}

// ─── 3. Brave LV3 Search ────────────────────────────────────

// ─── 3. Search APIs ────────────────────────────────────

const BRAVE_API_KEY = 'BSAFdovbMjUmOLqHWYSmrFqgaH2gMiL';
const FELO_API_KEY = 'fk-i2h2BcorKd7qTHVeMkwa7AQiT0yYMviPmnhPz9emSBPkGdFy';

// Brave: Quick web search
function braveSearch(query) {
    return new Promise((resolve) => {
        const url = new URL('https://api.search.brave.com/res/v1/web/search');
        url.searchParams.set('q', query);
        url.searchParams.set('count', '5');
        
        const options = {
            hostname: 'api.search.brave.com',
            path: url.pathname + url.search,
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'X-Subscription-Token': BRAVE_API_KEY
            }
        };
        
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const json = JSON.parse(data);
                    const results = json.results || [];
                    const formatted = results.map(r => 
                        `${r.title}\n  ${r.url}\n  ${(r.description || '').substring(0, 150)}`
                    ).join('\n\n');
                    resolve(formatted || 'No results found');
                } catch {
                    resolve('Parse error');
                }
            });
        });
        
        req.on('error', e => resolve('Brave Error: ' + e.message));
        req.setTimeout(15000, () => { req.destroy(); resolve('Timeout'); });
        req.end();
    });
}

// Felo: AI-synthesized deep research (15-40 sources)
function feloResearch(query) {
    return new Promise((resolve) => {
        const postData = JSON.stringify({ query });
        
        const options = {
            hostname: 'openapi.felo.ai',
            path: '/v2/chat',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${FELO_API_KEY}`,
                'Content-Length': Buffer.byteLength(postData)
            }
        };
        
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const json = JSON.parse(data);
                    const answer = json.data?.answer || 'No answer';
                    const sources = (json.data?.resources || []).slice(0, 5)
                        .map(r => `- ${r.title}: ${r.link}`)
                        .join('\n');
                    resolve(`${answer}\n\nSources:\n${sources}`);
                } catch {
                    resolve('Felo parse error');
                }
            });
        });
        
        req.on('error', e => resolve('Felo Error: ' + e.message));
        req.setTimeout(20000, () => { req.destroy(); resolve('Timeout'); });
        req.write(postData);
        req.end();
    });
}

// ─── 4. Risk Classification ────────────────────────────────

const EXEC_TYPES = new Set([
    'application/x-dosexec', 'application/x-executable',
    'application/x-sharedlib', 'application/x-mach-binary', 
    'application/vnd.microsoft.portable-executable',
    'pebin', 'elf', 'macho', 'dosbin', 'winexe', 'dexbin',
    'x-dosexec', 'x-executable', 'x-sharedlib'
]);

const SCRIPT_TYPES = new Set([
    'text/x-python', 'text/x-java', 'text/x-php', 'application/x-sh',
    'text/x-shellscript', 'application/x-powershell', 'text/x-ruby',
    'text/x-javascript', 'text/x-perl', 'text/x-typescript', 'python'
]);

function classifyRisk(scans) {
    let risk = 'LOW';
    const reasons = [];
    
    for (const scan of scans) {
        const pred = scan.predicted.toLowerCase();
        const ext = path.extname(scan.file).toLowerCase();
        
        // Check if predicted contains executable type
        const isExecType = EXEC_TYPES.has(pred) || 
            pred.includes('x-dosexec') || 
            pred.includes('pebin') || 
            pred.includes('executable');
        
        if (isExecType) {
            if (['.py','.js','.ts','.ps1','.sh','.rb','.php'].includes(ext)) {
                risk = 'HIGH';
                reasons.push(`🚫 ${path.basename(scan.file)}: ${scan.predicted} + ${ext} = BLOCK`);
            } else {
                risk = 'MEDIUM';
                reasons.push(`🟡 ${path.basename(scan.file)}: ${scan.predicted} (executable)`);
            }
        } else if (SCRIPT_TYPES.has(pred) || pred.includes('python') || pred.includes('javascript')) {
            reasons.push(`🟢 ${path.basename(scan.file)}: ${scan.predicted}`);
        } else {
            risk = 'MEDIUM';
            reasons.push(`⚪ ${path.basename(scan.file)}: ${scan.predicted || 'unknown'}`);
        }
    }
    
    return { risk, reasons };
}

// ─── 5. Main Pipeline ──────────────────────────────────────

async function main() {
    const args = process.argv.slice(2);
    const command = args.find(a => !a.startsWith('--')) || 'echo no command';
    const auto = args.includes('--auto');
    
    console.log('\n🔍 MAGIKA + BRAVE LV3 + OPENCLAW EXEC 聯動');
    console.log('═'.repeat(50));
    console.log(`📌 Command: ${command}`);
    
    // Step 1: Extract files
    console.log('\n[Step 1] Extract file paths...');
    const files = extractFilePaths(command);
    console.log(`   Found: ${files.length ? files.map(f => path.basename(f)).join(', ') : '(none)'}`);
    
    // Step 2: Magika Scan
    console.log('\n[Step 2] Magika AI scan...');
    let scans = [];
    try {
        scans = await magikaScan(command);
        for (const s of scans) {
            console.log(`   🌀 ${path.basename(s.file)}`);
            console.log(`      → ${s.predicted} (${s.label}) | Score: ${s.score}`);
        }
        if (!scans.length) console.log('   (no files found in command)');
    } catch (e) {
        console.log(`   ⚠️ Magika error: ${e.message.substring(0, 100)}`);
    }
    
    // Step 3: Classify Risk
    console.log('\n[Step 3] Risk classification...');
    const { risk, reasons } = classifyRisk(scans);
    for (const r of reasons) console.log(`   ${r}`);
    if (!reasons.length) console.log('   (no files)');
    console.log(`\n   🎯 Risk Level: ${risk}`);
    
    // Step 4: Research (Brave + Felo)
    console.log('\n[Step 4] Security research...');
    if (risk !== 'LOW' && files.length > 0) {
        for (const f of files) {
            const basename = path.basename(f);
            const query = `${basename} malware security github`;
            
            // Brave: Quick threat intel
            console.log(`   🌐 Brave: ${query}`);
            const braveResults = await braveSearch(query);
            const braveLines = braveResults.split('\n').filter(l => l.trim()).slice(0, 3);
            for (const l of braveLines) console.log(`      ${l.substring(0, 100)}`);
            
            // Felo: Deep AI research
            console.log(`   🔍 Felo AI: ${query}`);
            const feloResults = await feloResearch(query);
            const feloLines = feloResults.split('\n').filter(l => l.trim()).slice(0, 6);
            for (const l of feloLines) console.log(`      ${l.substring(0, 100)}`);
        }
    } else {
        console.log('   (skipped - LOW risk)');
    }
    
    // Step 5: Execution Decision
    console.log('\n[Step 5] Execution decision...');
    
    if (risk === 'HIGH') {
        console.log('   🚫 BLOCKED: Binary masquerading as script');
        process.exit(2);
    }
    
    if (risk === 'MEDIUM' && !auto) {
        console.log('   ⚠️  MEDIUM RISK: Manual review required');
        console.log('   Run with --auto to proceed anyway');
        process.exit(1);
    }
    
    if (risk === 'MEDIUM' && auto) {
        console.log('   ⚠️  AUTO-MODE: Proceeding despite MEDIUM risk');
    }
    
    if (risk === 'LOW') {
        console.log('   ✅ LOW RISK: Proceeding with exec...');
    }
    
    // Step 6: Execute
    console.log('\n[Step 6] Executing command...');
    try {
        const proc = spawn(command, { 
            shell: true, 
            stdio: 'inherit',
            timeout: 60000
        });
        proc.on('close', code => {
            console.log(`\n✅ Exit: ${code}`);
            process.exit(code || 0);
        });
    } catch (e) {
        console.log(`   ❌ Exec error: ${e.message}`);
        process.exit(1);
    }
}

main().catch(e => {
    console.error('Fatal:', e);
    process.exit(1);
});
