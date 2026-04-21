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

    console.log('[OTP] リクエスト受信 - targetEmail:', targetEmail);

    if (!host || !port || !user || !pass) {
        return res.json({
            status: 'error',
            message: 'host, port, user, pass は必須です'
        });
    }

    if (!targetEmail) {
        return res.json({
            status: 'error',
            message: 'targetEmailは必須です'
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
        result.requestedTargetEmail = targetEmail;
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

// OTP取得（v3.7.6方式：シンプルに最新1件）
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
                // 検索条件：未読 + パスコード + TO（targetEmail指定時）
                const searchCriteria = ['UNSEEN', ['SUBJECT', 'パスコード']];
                if (targetEmail) {
                    searchCriteria.push(['TO', targetEmail]);
                }

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
                            message: '未読メールなし',
                            searchCriteria: JSON.stringify(searchCriteria),
                            targetEmail: targetEmail || 'none'
                        });
                    }

                    // 最新の1件だけ取得
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
                                const toHeader = parsed.to ? parsed.to.text : '';

                                console.log('取得メール - To:', toHeader, 'Subject:', subject.substring(0, 30));

                                // パスコードメールかチェック
                                if (!subject.includes('パスコード')) {
                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'pending',
                                        message: '最新の未読メールはパスコードメールではない',
                                        subject: subject
                                    });
                                }

                                // 3分以内のメールか確認
                                const now = new Date();
                                const ageMinutes = (now - date) / 1000 / 60;

                                if (ageMinutes > 3) {
                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'pending',
                                        message: 'パスコードが古い（3分超過）',
                                        ageMinutes: Math.round(ageMinutes),
                                        subject: subject
                                    });
                                }

                                // パスコード抽出
                                const match = body.match(/(\d{6})/);

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
                                        toHeader: toHeader,
                                        targetEmail: targetEmail
                                    });
                                }

                                resolved = true;
                                clearTimeout(timeout);
                                imap.end();
                                return resolve({
                                    status: 'error',
                                    message: 'パスコード抽出失敗',
                                    subject: subject,
                                    bodyPreview: body.substring(0, 300)
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
                            if (!resolved) {
                                searchRegUrl();
                            }
                        });
                    } else {
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

                                    if (!subject.includes('会員登録')) {
                                        resolved = true;
                                        clearTimeout(timeout);
                                        imap.end();
                                        return resolve({
                                            status: 'pending',
                                            message: '最新の未読メールは登録メールではない',
                                            subject: subject
                                        });
                                    }

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

                                    const urlMatch = body.match(/https:\/\/www\.pokemoncenter-online\.com\/new-customer\/\?token=[^\s\n\r]+/);

                                    if (urlMatch) {
                                        imap.addFlags([latestUid], ['\\Seen'], () => {});
                                        
                                        resolved = true;
                                        clearTimeout(timeout);
                                        imap.end();
                                        return resolve({
                                            status: 'success',
                                            url: urlMatch[0],
                                            ageMinutes: Math.round(ageMinutes),
                                            messageDate: date.toISOString(),
                                            subject: subject
                                        });
                                    }

                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'error',
                                        message: '登録URL抽出失敗',
                                        subject: subject,
                                        bodyPreview: body.substring(0, 500)
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

                    // 最新の1件だけ取得
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
                                const subject = parsed.subject || '';
                                const body = parsed.text || '';
                                const date = parsed.date;

                                if (!subject.includes('認証コード')) {
                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'pending',
                                        message: '認証コードメールではない',
                                        subject: subject
                                    });
                                }

                                const now = new Date();
                                const ageMinutes = (now - date) / 1000 / 60;

                                if (ageMinutes > 5) {
                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'pending',
                                        message: '認証コードが古い（5分超過）',
                                        ageMinutes: Math.round(ageMinutes)
                                    });
                                }

                                // カード下4桁で照合（指定がある場合）
                                if (cardLast4 && !body.includes(cardLast4)) {
                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'pending',
                                        message: 'カード番号不一致',
                                        cardLast4: cardLast4
                                    });
                                }

                                // 認証コード抽出
                                let otp_code = null;

                                function isDateOrYear(num) {
                                    if (num >= 202000 && num <= 203099) return true;
                                    const yy = Math.floor(num / 10000);
                                    const mm = Math.floor((num % 10000) / 100);
                                    const dd = num % 100;
                                    if (yy >= 20 && yy <= 35 && mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31) return true;
                                    return false;
                                }

                                let match = body.match(/認証コード[^\d]*(\d{6})/);
                                if (match && !isDateOrYear(parseInt(match[1]))) {
                                    otp_code = match[1];
                                }

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
                                    imap.addFlags([latestUid], ['\\Seen'], () => {});

                                    resolved = true;
                                    clearTimeout(timeout);
                                    imap.end();
                                    return resolve({
                                        status: 'success',
                                        code: otp_code,
                                        ageMinutes: Math.round(ageMinutes),
                                        messageDate: date.toISOString(),
                                        subject: subject
                                    });
                                }

                                resolved = true;
                                clearTimeout(timeout);
                                imap.end();
                                return resolve({
                                    status: 'error',
                                    message: '認証コード抽出失敗',
                                    subject: subject,
                                    bodyPreview: body.substring(0, 300)
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
