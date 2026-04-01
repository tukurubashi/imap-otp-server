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
                // 検索条件を構築（件名に「パスコード」を含む未読メールのみ、日付フィルタなし）
                const searchCriteria = ['UNSEEN', ['SUBJECT', 'パスコード']];
                if (targetEmail) {
                    searchCriteria.push(['TO', targetEmail]);
                }

                imap.search(searchCriteria, (err, results) => {
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
