// v2 - force rebuild
const express = require('express');
const Imap = require('imap');
const { simpleParser } = require('mailparser');

const app = express();
app.use(express.json());

// CORS対応
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

// ヘルスチェック
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'IMAP OTP Server is running' });
});

// OTP取得エンドポイント
app.all('/api/otp', async (req, res) => {
    const params = req.method === 'POST' ? req.body : req.query;
    const { host, port, user, pass, security, targetEmail } = params;

    if (!host || !port || !user || !pass) {
        return res.json({
            status: 'error',
            message: 'host, port, user, pass は必須です'
        });
    }

    const imapConfig = {
        user: user,
        password: pass,
        host: host,
        port: parseInt(port, 10),
        tls: security === 'SSL/TLS' || security === 'ssl' || security === 'tls' || port === '993',
        tlsOptions: { rejectUnauthorized: false },
        authTimeout: 15000,
        connTimeout: 15000
    };

    try {
        const result = await fetchOTP(imapConfig, targetEmail);
        return res.json(result);
    } catch (err) {
        return res.json({
            status: 'error',
            message: err.message
        });
    }
});

// 登録URL取得エンドポイント
app.all('/api/regurl', async (req, res) => {
    const params = req.method === 'POST' ? req.body : req.query;
    const { host, port, user, pass, security, targetEmail } = params;

    if (!host || !port || !user || !pass) {
        return res.json({
            status: 'error',
            message: 'host, port, user, pass は必須です'
        });
    }

    const imapConfig = {
        user: user,
        password: pass,
        host: host,
        port: parseInt(port, 10),
        tls: security === 'SSL/TLS' || security === 'ssl' || security === 'tls' || port === '993',
        tlsOptions: { rejectUnauthorized: false },
        authTimeout: 15000,
        connTimeout: 15000
    };

    try {
        const result = await fetchRegUrl(imapConfig, targetEmail);
        return res.json(result);
    } catch (err) {
        return res.json({
            status: 'error',
            message: err.message
        });
    }
});

// 3Dセキュア認証コード取得エンドポイント
app.all('/api/3dsecure', async (req, res) => {
    const params = req.method === 'POST' ? req.body : req.query;
    const { host, port, user, pass, security, cardLast4 } = params;

    if (!host || !port || !user || !pass) {
        return res.json({
            status: 'error',
            message: 'host, port, user, pass は必須です'
        });
    }

    const imapConfig = {
        user: user,
        password: pass,
        host: host,
        port: parseInt(port, 10),
        tls: security === 'SSL/TLS' || security === 'ssl' || security === 'tls' || port === '993',
        tlsOptions: { rejectUnauthorized: false },
        authTimeout: 15000,
        connTimeout: 15000
    };

    try {
        const result = await fetch3DSecureOTP(imapConfig, cardLast4);
        return res.json(result);
    } catch (err) {
        return res.json({
            status: 'error',
            message: err.message
        });
    }
});

// targetEmailに一致するメールを探す関数
async function checkEmailsForTarget(imap, uids, targetEmail, timeout, callback) {
    const { simpleParser } = require('mailparser');
    
    for (const uid of uids) {
        try {
            const result = await new Promise((resolve, reject) => {
                const fetch = imap.fetch([uid], { bodies: '', markSeen: false });
                let emailData = '';
                
                fetch.on('message', (msg) => {
                    msg.on('body', (stream) => {
                        stream.on('data', (chunk) => {
                            emailData += chunk.toString('utf8');
                        });
                    });
                    
                    msg.once('end', async () => {
                        try {
                            const parsed = await simpleParser(emailData);
                            const toHeader = parsed.to ? parsed.to.text : '';
                            const subject = parsed.subject || '';
                            const body = parsed.text || '';
                            const date = parsed.date;
                            
                            console.log(`チェック中 UID:${uid} To:${toHeader} Subject:${subject.substring(0, 30)}`);
                            
                            // ToヘッダーにtargetEmailが含まれているかチェック
                            if (toHeader.toLowerCase().includes(targetEmail.toLowerCase())) {
                                // パスコードメールかチェック
                                if (!subject.includes('パスコード')) {
                                    resolve({ match: false });
                                    return;
                                }
                                
                                // 10分以内のメールか確認
                                const now = new Date();
                                const ageMinutes = (now - date) / 1000 / 60;
                                
                                if (ageMinutes > 10) {
                                    resolve({ match: false, reason: 'old' });
                                    return;
                                }
                                
                                // パスコード抽出
                                const codeMatch = body.match(/(\d{6})/);
                                if (codeMatch) {
                                    // 既読にする
                                    imap.addFlags([uid], ['\\Seen'], () => {});
                                    
                                    resolve({
                                        match: true,
                                        status: 'success',
                                        code: codeMatch[1],
                                        ageMinutes: Math.round(ageMinutes),
                                        messageDate: date.toISOString(),
                                        subject: subject,
                                        toHeader: toHeader
                                    });
                                    return;
                                }
                            }
                            
                            resolve({ match: false });
                        } catch (e) {
                            resolve({ match: false, error: e.message });
                        }
                    });
                });
                
                fetch.once('error', (err) => {
                    resolve({ match: false, error: err.message });
                });
            });
            
            if (result.match && result.status === 'success') {
                callback(result);
                return;
            }
        } catch (e) {
            console.log('メールチェックエラー:', e.message);
        }
    }
    
    // 一致するメールが見つからなかった
    callback({
        status: 'pending',
        message: '対象メールアドレス宛のメールが見つかりません',
        targetEmail: targetEmail,
        checkedCount: uids.length
    });
}

function fetchOTP(config, targetEmail) {
    return new Promise((resolve, reject) => {
        const imap = new Imap(config);
        let resolved = false;
        let currentPhase = 'init';

        console.log('IMAP接続開始:', config.host, config.port, config.user);

        const timeout = setTimeout(() => {
            if (!resolved) {
                resolved = true;
                try { imap.end(); } catch(e) {}
                resolve({ status: 'pending', message: 'タイムアウト（90秒）', phase: currentPhase });
            }
        }, 90000);

        imap.once('error', (err) => {
            console.log('IMAPエラー:', err.message);
            if (!resolved) {
                resolved = true;
                clearTimeout(timeout);
                resolve({ status: 'error', message: 'IMAP接続エラー: ' + err.message, phase: currentPhase });
            }
        });

        imap.once('ready', () => {
            console.log('IMAP ready');
            currentPhase = 'ready';
            imap.openBox('INBOX', false, (err, box) => {
                console.log('INBOX opened');
                currentPhase = 'openbox';
                if (err) {
                    resolved = true;
                    clearTimeout(timeout);
                    imap.end();
                    return resolve({ status: 'error', message: 'INBOX開けない: ' + err.message, phase: 'openbox' });
                }

                currentPhase = 'search';
                // 検索条件を構築（件名に「パスコード」を含む未読メールのみ）
                // 注意: GmailのIMAPでは['TO', email]が正しく動かないことがあるため、
                // 検索後にJavaScript側でToヘッダーをチェックする
                const searchCriteria = ['UNSEEN', ['SUBJECT', 'パスコード']];
                
                console.log('検索条件:', JSON.stringify(searchCriteria));
                console.log('targetEmail:', targetEmail);

                imap.search(searchCriteria, (err, results) => {
                    console.log('検索結果数:', results ? results.length : 0);
                    currentPhase = 'search_done';
                    if (err) {
                        resolved = true;
                        clearTimeout(timeout);
                        imap.end();
                        return resolve({ status: 'error', message: '検索エラー: ' + err.message, phase: 'search' });
                    }

                    if (!results || results.length === 0) {
                        resolved = true;
                        clearTimeout(timeout);
                        imap.end();
                        return resolve({ 
                            status: 'pending', 
                            message: '未読メールなし',
                            searchCriteria: JSON.stringify(searchCriteria),
                            targetEmail: targetEmail || 'none'
                        });
                    }

                    // targetEmailが指定されている場合、全件取得してToヘッダーでフィルタリング
                    if (targetEmail) {
                        // 新しい順（後ろから）にチェックしていく
                        const uidsToCheck = results.slice().reverse();
                        checkEmailsForTarget(imap, uidsToCheck, targetEmail, timeout, (result) => {
                            resolved = true;
                            clearTimeout(timeout);
                            imap.end();
                            resolve(result);
                        });
                        return;
                    }

                    // targetEmailなしの場合は従来通り最新のメールを取得
                    const unseenCount = results.length;
                    const latestUid = results[results.length - 1];
                    const fetch = imap.fetch([latestUid], { bodies: '', markSeen: false });

                    fetch.on('message', (msg) => {
                        let emailData = '';

                        msg.on('body', (stream) => {
                            stream.on('data', (chunk) => {
                                emailData += chunk.toString('utf8');
                            });
                        });

                        msg.once('end', async () => {
                            try {
                                const parsed = await simpleParser(emailData);
                                const body = parsed.text || '';
                                const subject = parsed.subject || '';
                                const date = parsed.date;
                                const toHeader = parsed.to ? (parsed.to.text || JSON.stringify(parsed.to)) : 'none';
                                
                                console.log('取得メール - To:', toHeader, 'Subject:', subject);

                                // パスコードメールかチェック
                                if (!subject.includes('パスコード')) {
                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'pending',
                                        message: '最新の未読メールはパスコードメールではない',
                                        subject: subject,
                                        unseenCount: unseenCount
                                    });
                                }

                                // 10分以内のメールか確認
                                const now = new Date();
                                const ageMinutes = (now - date) / 1000 / 60;

                                if (ageMinutes > 10) {
                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'pending',
                                        message: 'パスコードが古い（10分超過）',
                                        ageMinutes: Math.round(ageMinutes),
                                        subject: subject
                                    });
                                }

                                // パスコード抽出（6桁数字）
                                const match = body.match(/【パスコード】\s*(\d{6})/) || body.match(/(\d{6})/);

                                if (match) {
                                    // 既読にする
                                    imap.addFlags([latestUid], ['\\Seen'], () => {});
                                    
                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'success',
                                        code: match[1],
                                        ageMinutes: Math.round(ageMinutes),
                                        messageDate: date.toISOString(),
                                        subject: subject,
                                        unseenCount: unseenCount
                                    });
                                }

                                resolved = true;
                                clearTimeout(timeout);
                                imap.end();
                                return resolve({
                                    status: 'error',
                                    message: 'パスコード抽出失敗',
                                    subject: subject,
                                    bodyPreview: body.substring(0, 300),
                                    unseenCount: unseenCount
                                });
                            } catch (parseErr) {
                                resolved = true;
                                clearTimeout(timeout);
                                imap.end();
                                return resolve({ status: 'error', message: 'メール解析エラー: ' + parseErr.message, phase: 'parse' });
                            }
                        });
                    });

                    fetch.once('error', (err) => {
                        resolved = true;
                        clearTimeout(timeout);
                        imap.end();
                        resolve({ status: 'error', message: 'Fetchエラー: ' + err.message, phase: 'fetch' });
                    });

                    fetch.once('end', () => {
                        if (!resolved) {
                            setTimeout(() => {
                                if (!resolved) {
                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    resolve({ status: 'pending', message: 'メール取得完了待ち', phase: 'fetch_end' });
                                }
                            }, 5000);
                        }
                    });
                });
            });
        });

        imap.connect();
    });
}

// 登録URL取得関数
function fetchRegUrl(config, targetEmail) {
    return new Promise((resolve, reject) => {
        const imap = new Imap(config);
        let resolved = false;
        let currentPhase = 'init';

        console.log('IMAP接続開始 (regurl):', config.host, config.port, config.user);

        const timeout = setTimeout(() => {
            if (!resolved) {
                resolved = true;
                try { imap.end(); } catch(e) {}
                resolve({ status: 'pending', message: 'タイムアウト（90秒）', phase: currentPhase });
            }
        }, 90000);

        imap.once('error', (err) => {
            console.log('IMAPエラー:', err.message);
            if (!resolved) {
                resolved = true;
                clearTimeout(timeout);
                resolve({ status: 'error', message: 'IMAP接続エラー: ' + err.message, phase: currentPhase });
            }
        });

        imap.once('ready', () => {
            console.log('IMAP ready (regurl)');
            currentPhase = 'ready';
            imap.openBox('INBOX', false, (err, box) => {
                console.log('INBOX opened (regurl)');
                currentPhase = 'openbox';
                if (err) {
                    resolved = true;
                    clearTimeout(timeout);
                    imap.end();
                    return resolve({ status: 'error', message: 'INBOX開けない: ' + err.message, phase: 'openbox' });
                }

                currentPhase = 'search';
                
                // 登録メールと「既に登録済み」メールの両方を検索
                const regSearchCriteria = ['UNSEEN', ['SUBJECT', '会員登録の手続き']];
                const dupSearchCriteria = ['UNSEEN', ['SUBJECT', '既に登録済み']];
                
                if (targetEmail) {
                    regSearchCriteria.push(['TO', targetEmail]);
                    dupSearchCriteria.push(['TO', targetEmail]);
                }

                // まず「既に登録済み」メールを検索
                imap.search(dupSearchCriteria, (err, dupResults) => {
                    if (err) {
                        console.log('既登録メール検索エラー:', err.message);
                    }

                    // 「既に登録済み」メールがあるか確認
                    if (dupResults && dupResults.length > 0) {
                        const latestDupUid = dupResults[dupResults.length - 1];
                        const dupFetch = imap.fetch([latestDupUid], { bodies: '', markSeen: false });
                        
                        dupFetch.on('message', (msg) => {
                            let emailData = '';
                            msg.on('body', (stream) => {
                                stream.on('data', (chunk) => {
                                    emailData += chunk.toString('utf8');
                                });
                            });
                            msg.once('end', async () => {
                                try {
                                    const parsed = await simpleParser(emailData);
                                    const date = parsed.date;
                                    const now = new Date();
                                    const ageMinutes = (now - date) / 1000 / 60;

                                    // 10分以内なら「既に登録済み」として処理
                                    if (ageMinutes <= 10) {
                                        imap.addFlags([latestDupUid], ['\\Seen'], () => {});
                                        resolved = true;
                                        clearTimeout(timeout);
                                        imap.end();
                                        return resolve({
                                            status: 'skip',
                                            message: 'メールアドレスは既に登録済みです',
                                            ageMinutes: Math.round(ageMinutes)
                                        });
                                    }
                                } catch (e) {
                                    console.log('既登録メール解析エラー:', e.message);
                                }
                            });
                        });
                        
                        dupFetch.once('end', () => {
                            // 既登録チェック完了後、登録URLメールを検索
                            if (!resolved) {
                                searchRegUrl();
                            }
                        });
                    } else {
                        // 「既に登録済み」メールがない場合、直接登録URLを検索
                        searchRegUrl();
                    }
                });

                function searchRegUrl() {
                    imap.search(regSearchCriteria, (err, results) => {
                        currentPhase = 'search_done';
                        if (err) {
                            resolved = true;
                            clearTimeout(timeout);
                            imap.end();
                            return resolve({ status: 'error', message: '検索エラー: ' + err.message, phase: 'search' });
                        }

                        if (!results || results.length === 0) {
                            resolved = true;
                            clearTimeout(timeout);
                            imap.end();
                            return resolve({ 
                                status: 'pending', 
                                message: '未読の登録メールなし',
                                searchCriteria: JSON.stringify(regSearchCriteria),
                                targetEmail: targetEmail || 'none'
                            });
                        }

                        const unseenCount = results.length;
                        const latestUid = results[results.length - 1];
                        const fetch = imap.fetch([latestUid], { bodies: '', markSeen: false });

                        fetch.on('message', (msg) => {
                            let emailData = '';

                            msg.on('body', (stream) => {
                                stream.on('data', (chunk) => {
                                    emailData += chunk.toString('utf8');
                                });
                            });

                            msg.once('end', async () => {
                                try {
                                    const parsed = await simpleParser(emailData);
                                    const body = parsed.text || '';
                                    const subject = parsed.subject || '';
                                    const date = parsed.date;

                                    // 登録メールかチェック
                                    if (!subject.includes('会員登録')) {
                                        resolved = true;
                                        clearTimeout(timeout);
                                        imap.end();
                                        return resolve({
                                            status: 'pending',
                                            message: '最新の未読メールは登録メールではない',
                                            subject: subject,
                                            unseenCount: unseenCount
                                        });
                                    }

                                    // 10分以内のメールか確認
                                    const now = new Date();
                                    const ageMinutes = (now - date) / 1000 / 60;

                                    if (ageMinutes > 10) {
                                        resolved = true;
                                        clearTimeout(timeout);
                                        imap.end();
                                        return resolve({
                                            status: 'pending',
                                            message: '登録メールが古い（10分超過）',
                                            ageMinutes: Math.round(ageMinutes),
                                            subject: subject
                                        });
                                    }

                                    // 登録URL抽出
                                    // パターン: https://www.pokemoncenter-online.com/new-customer/?token=...
                                    const urlMatch = body.match(/https:\/\/www\.pokemoncenter-online\.com\/new-customer\/\?token=[^\s\n\r]+/);

                                    if (urlMatch) {
                                        // 既読にする
                                        imap.addFlags([latestUid], ['\\Seen'], () => {});
                                        
                                        resolved = true;
                                        clearTimeout(timeout);
                                        imap.end();
                                        return resolve({
                                            status: 'success',
                                            url: urlMatch[0],
                                            ageMinutes: Math.round(ageMinutes),
                                            messageDate: date.toISOString(),
                                            subject: subject,
                                            unseenCount: unseenCount
                                        });
                                    }

                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'error',
                                        message: '登録URL抽出失敗',
                                        subject: subject,
                                        bodyPreview: body.substring(0, 500),
                                        unseenCount: unseenCount
                                    });
                                } catch (parseErr) {
                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({ status: 'error', message: 'メール解析エラー: ' + parseErr.message, phase: 'parse' });
                                }
                            });
                        });

                        fetch.once('error', (err) => {
                            resolved = true;
                            clearTimeout(timeout);
                            imap.end();
                            resolve({ status: 'error', message: 'Fetchエラー: ' + err.message, phase: 'fetch' });
                        });

                        fetch.once('end', () => {
                            if (!resolved) {
                                setTimeout(() => {
                                    if (!resolved) {
                                        resolved = true;
                                        clearTimeout(timeout);
                                        imap.end();
                                        resolve({ status: 'pending', message: 'メール取得完了待ち', phase: 'fetch_end' });
                                    }
                                }, 5000);
                            }
                        });
                    });
                }
            });
        });

        imap.connect();
    });
}

// 3Dセキュア認証コード取得関数
function fetch3DSecureOTP(config, cardLast4) {
    return new Promise((resolve, reject) => {
        const imap = new Imap(config);
        let resolved = false;
        let currentPhase = 'init';

        console.log('IMAP接続開始 (3Dセキュア):', config.host, config.port, config.user);
        if (cardLast4) {
            console.log('カード下4桁:', cardLast4);
        }

        const timeout = setTimeout(() => {
            if (!resolved) {
                resolved = true;
                try { imap.end(); } catch(e) {}
                resolve({ status: 'pending', message: 'タイムアウト（90秒）', phase: currentPhase });
            }
        }, 90000);

        imap.once('error', (err) => {
            console.log('IMAPエラー:', err.message);
            if (!resolved) {
                resolved = true;
                clearTimeout(timeout);
                resolve({ status: 'error', message: 'IMAP接続エラー: ' + err.message, phase: currentPhase });
            }
        });

        imap.once('ready', () => {
            console.log('IMAP ready (3Dセキュア)');
            currentPhase = 'ready';
            imap.openBox('INBOX', false, (err, box) => {
                console.log('INBOX opened');
                currentPhase = 'openbox';
                if (err) {
                    resolved = true;
                    clearTimeout(timeout);
                    imap.end();
                    return resolve({ status: 'error', message: 'INBOX開けない: ' + err.message, phase: 'openbox' });
                }

                currentPhase = 'search';
                // マネーフォワードからの認証コードメールを検索
                const searchCriteria = [
                    'UNSEEN',
                    ['FROM', 'noreply-biz-pay@moneyforward.com'],
                    ['SUBJECT', '認証コード']
                ];

                console.log('検索条件:', JSON.stringify(searchCriteria));

                imap.search(searchCriteria, (err, results) => {
                    console.log('検索結果数:', results ? results.length : 0);
                    currentPhase = 'search_done';
                    if (err) {
                        resolved = true;
                        clearTimeout(timeout);
                        imap.end();
                        return resolve({ status: 'error', message: '検索エラー: ' + err.message, phase: 'search' });
                    }

                    if (!results || results.length === 0) {
                        resolved = true;
                        clearTimeout(timeout);
                        imap.end();
                        return resolve({ 
                            status: 'pending', 
                            message: '3Dセキュア認証メールなし',
                            searchCriteria: JSON.stringify(searchCriteria)
                        });
                    }

                    // 新しい順にチェック
                    const uidsToCheck = results.slice().reverse();
                    check3DSecureEmails(imap, uidsToCheck, cardLast4, timeout, (result) => {
                        resolved = true;
                        clearTimeout(timeout);
                        imap.end();
                        resolve(result);
                    });
                });
            });
        });

        imap.connect();
    });
}

// 3Dセキュアメールをチェックする関数
async function check3DSecureEmails(imap, uids, cardLast4, timeout, callback) {
    for (const uid of uids) {
        try {
            const result = await new Promise((resolve, reject) => {
                const fetch = imap.fetch([uid], { bodies: '', markSeen: false });
                let emailData = '';
                
                fetch.on('message', (msg) => {
                    msg.on('body', (stream) => {
                        stream.on('data', (chunk) => {
                            emailData += chunk.toString('utf8');
                        });
                    });
                    
                    msg.once('end', async () => {
                        try {
                            const parsed = await simpleParser(emailData);
                            const subject = parsed.subject || '';
                            const body = parsed.text || '';
                            const date = parsed.date;
                            
                            console.log(`チェック中 UID:${uid} Subject:${subject.substring(0, 40)}`);
                            
                            // 認証コードメールかチェック
                            if (!subject.includes('認証コード')) {
                                resolve({ match: false });
                                return;
                            }
                            
                            // 5分以内のメールか確認
                            const now = new Date();
                            const ageMinutes = (now - date) / 1000 / 60;
                            
                            if (ageMinutes > 5) {
                                console.log(`古いメール（${Math.round(ageMinutes)}分前）- スキップ`);
                                resolve({ match: false, reason: 'old' });
                                return;
                            }
                            
                            // カード下4桁で照合（指定がある場合）
                            if (cardLast4 && !body.includes(cardLast4)) {
                                console.log(`カード番号不一致（${cardLast4}が含まれていません）- スキップ`);
                                resolve({ match: false, reason: 'card_mismatch' });
                                return;
                            }
                            
                            // 認証コード抽出
                            let otp_code = null;
                            
                            // 日付・年号っぽい6桁を判定する関数
                            function isDateOrYear(num) {
                                // 年号: 202000-203099 (2020年〜2030年台)
                                if (num >= 202000 && num <= 203099) return true;
                                // YYMMDD形式: 240101〜301231
                                const yy = Math.floor(num / 10000);
                                const mm = Math.floor((num % 10000) / 100);
                                const dd = num % 100;
                                if (yy >= 20 && yy <= 35 && mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31) return true;
                                // MMDDYY形式: 月日年
                                const mm2 = Math.floor(num / 10000);
                                const dd2 = Math.floor((num % 10000) / 100);
                                const yy2 = num % 100;
                                if (mm2 >= 1 && mm2 <= 12 && dd2 >= 1 && dd2 <= 31 && yy2 >= 20 && yy2 <= 35) return true;
                                return false;
                            }
                            
                            // パターン1: 「認証コード」の直後
                            let match = body.match(/認証コード[^\d]*(\d{6})/);
                            if (match && !isDateOrYear(parseInt(match[1]))) {
                                otp_code = match[1];
                            }
                            
                            // パターン2: 「■ 認証コード」の後
                            if (!otp_code) {
                                match = body.match(/■\s*認証コード[^\d]*(\d{6})/);
                                if (match && !isDateOrYear(parseInt(match[1]))) {
                                    otp_code = match[1];
                                }
                            }
                            
                            // パターン3: 「ワンタイムパスワード」の後
                            if (!otp_code) {
                                match = body.match(/ワンタイムパスワード[^\d]*(\d{6})/);
                                if (match && !isDateOrYear(parseInt(match[1]))) {
                                    otp_code = match[1];
                                }
                            }
                            
                            // パターン4: 6桁の数字を探す（日付・年号除外）
                            if (!otp_code) {
                                const all_6digits = body.match(/\b(\d{6})\b/g);
                                if (all_6digits) {
                                    for (const candidate of all_6digits) {
                                        const num = parseInt(candidate);
                                        if (!isDateOrYear(num)) {
                                            otp_code = candidate;
                                            break;
                                        }
                                    }
                                }
                            }
                            
                            if (otp_code) {
                                // 既読にする
                                imap.addFlags([uid], ['\\Seen'], () => {});
                                
                                console.log(`✅ 3Dセキュア認証コード取得: ${otp_code}`);
                                
                                resolve({
                                    match: true,
                                    status: 'success',
                                    code: otp_code,
                                    ageMinutes: Math.round(ageMinutes),
                                    messageDate: date.toISOString(),
                                    subject: subject
                                });
                                return;
                            }
                            
                            resolve({ match: false, reason: 'no_code' });
                        } catch (e) {
                            resolve({ match: false, error: e.message });
                        }
                    });
                });
                
                fetch.once('error', (err) => {
                    resolve({ match: false, error: err.message });
                });
            });
            
            if (result.match && result.status === 'success') {
                callback(result);
                return;
            }
        } catch (e) {
            console.log('メールチェックエラー:', e.message);
        }
    }
    
    // 一致するメールが見つからなかった
    callback({
        status: 'pending',
        message: '3Dセキュア認証コードが見つかりません',
        cardLast4: cardLast4 || 'none',
        checkedCount: uids.length
    });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
