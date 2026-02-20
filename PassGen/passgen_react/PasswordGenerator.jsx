import React, { useState } from 'react';
import './PasswordGenerator.css'; // 同一ディレクトリにCSSを配置する場合

const CHAR_SETS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()_+~`|}{[]:;?><,./-="
};

export default function PasswordGenerator() {
  const [password, setPassword] = useState('パスワードを生成してください');
  const [length, setLength] = useState(16);
  const [options, setOptions] = useState({
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true
  });
  const [status, setStatus] = useState({ type: '', message: '' });
  const [isCopied, setIsCopied] = useState(false);

  // オプション（チェックボックス）の変更ハンドラー
  const handleOptionChange = (e) => {
    const { name, checked } = e.target;
    setOptions(prev => ({ ...prev, [name]: checked }));
  };

  // SHA-1ハッシュ化関数 (Web Crypto API)
  const sha1 = async (string) => {
    const buffer = new TextEncoder().encode(string);
    const hash = await crypto.subtle.digest('SHA-1', buffer);
    const hashArray = Array.from(new Uint8Array(hash));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  };

  // k-匿名性を用いた漏洩チェック
  const checkPwnedPassword = async (pwd) => {
    setStatus({ type: 'loading', message: '漏洩データベースと照合中...' });

    try {
      const hash = await sha1(pwd);
      const prefix = hash.substring(0, 5);
      const suffix = hash.substring(5);

      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (!response.ok) throw new Error('Network response was not ok');
      const text = await response.text();
      
      const pwnedList = text.split('\n').map(line => line.split(':')[0]);
      
      if (pwnedList.includes(suffix)) {
        setStatus({ 
          type: 'danger', 
          message: '⚠️ 警告: このパスワードは過去のデータ漏洩で発見されています。' 
        });
      } else {
        setStatus({ 
          type: 'safe', 
          message: '✅ 安全: 既知の漏洩データベースには見つかりませんでした。' 
        });
      }
    } catch (error) {
      console.error("Pwned API error:", error);
      setStatus({ 
        type: 'loading', 
        message: '照合APIに接続できませんでしたが、パスワードは生成されました。' 
      });
    }
  };

  // パスワード生成と照合の実行
  const generateAndCheck = async () => {
    let charPool = "";
    if (options.uppercase) charPool += CHAR_SETS.uppercase;
    if (options.lowercase) charPool += CHAR_SETS.lowercase;
    if (options.numbers) charPool += CHAR_SETS.numbers;
    if (options.symbols) charPool += CHAR_SETS.symbols;

    if (charPool === "") {
      alert("少なくとも1つの文字種を選択してください。");
      return;
    }

    let newPassword = "";
    const randomValues = new Uint32Array(length);
    window.crypto.getRandomValues(randomValues);
    
    for (let i = 0; i < length; i++) {
      newPassword += charPool[randomValues[i] % charPool.length];
    }

    setPassword(newPassword);
    await checkPwnedPassword(newPassword);
    setIsCopied(false); // 生成し直したらコピー状態をリセット
  };

  // クリップボードへのコピー
  const copyToClipboard = () => {
    if (password === "パスワードを生成してください") return;
    
    navigator.clipboard.writeText(password).then(() => {
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    });
  };

  return (
    <div className="pg-wrapper">
      <div className="pg-container">
        <h2>NIST準拠 ジェネレーター</h2>
        <div className="pg-password-display">{password}</div>
        
        <div className="pg-options">
          <div className="pg-option-group">
            <label htmlFor="length">パスワード長 (NIST推奨: 8以上): <span>{length}</span></label>
            <input 
              type="range" 
              id="length" 
              min="8" 
              max="64" 
              value={length} 
              onChange={(e) => setLength(Number(e.target.value))} 
            />
          </div>
          
          {Object.keys(options).map((key) => (
            <div className="pg-option-group" key={key}>
              <label>
                <input 
                  type="checkbox" 
                  name={key} 
                  checked={options[key]} 
                  onChange={handleOptionChange} 
                /> 
                {key === 'uppercase' && ' 大文字 (A-Z)'}
                {key === 'lowercase' && ' 小文字 (a-z)'}
                {key === 'numbers' && ' 数字 (0-9)'}
                {key === 'symbols' && ' 記号 (!@#$%^&*)'}
              </label>
            </div>
          ))}
        </div>

        <button className="pg-btn" onClick={generateAndCheck}>
          パスワードを生成＆漏洩チェック
        </button>
        <button className="pg-btn pg-btn-secondary" onClick={copyToClipboard}>
          {isCopied ? "コピーしました！" : "クリップボードにコピー"}
        </button>

        {status.message && (
          <div className={`pg-status ${status.type}`}>
            {status.message}
          </div>
        )}
      </div>
    </div>
  );
}
