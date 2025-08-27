# 実務で使える JWT 認証 完全ガイド


## この資料で習得できること

- 🔍 JWT の内部構造とトークン検証の仕組み
- 🏗️ スケーラブルな認証アーキテクチャの設計
- 🛡️ OWASP に準拠したセキュリティ対策
- 🚀 React/Next.js での実装パターンと最適化
- 🔧 本番運用での監視・ログ・トラブルシューティング

## JWT の内部構造と検証メカニズム

### なぜ JWT を使うのか？

従来のセッション認証では、サーバーがセッション情報をデータベースやメモリに保存し、毎回照会する必要があります。一方 JWT は**自己完結型**で、トークン自体にユーザー情報と署名が含まれているため、サーバーは署名検証のみでユーザーを識別できます。

### JWT の構成要素（Header.Payload.Signature）

```javascript
// JWT の実際の構造（3つの部分を「.」で区切り）
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
//            ↑Header部分             ↑Payload部分                                                    ↑Signature部分

// 1. Header: 署名アルゴリズムとトークンタイプを指定
{
  "alg": "HS256",    // HMAC SHA256で署名
  "typ": "JWT"       // JWTトークンであることを明示
}

// 2. Payload (Claims): 実際のユーザー情報と権限
{
  "sub": "1234567890",           // Subject (ユーザーID) - 必須
  "name": "John Doe",            // カスタムクレーム（独自情報）
  "iat": 1516239022,            // Issued At (発行時刻) - UNIXタイムスタンプ
  "exp": 1516242622,            // Expiration (有効期限) - 必須
  "iss": "auth.example.com",     // Issuer (発行者) - どのサーバーが発行したか
  "aud": "api.example.com"      // Audience (対象者) - どのサーバー向けか
}

// 3. Signature: 改ざん検知のための署名
// HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
// サーバーの秘密鍵で署名することで、クライアントでの改ざんを防止
```

## 共通鍵方式 vs 公開鍵方式

### 共通鍵方式（対称暗号）- HMAC

**特徴:**
- 署名生成と検証に同じ秘密鍵を使用
- シンプルで高速
- 鍵の共有が必要

**アルゴリズム:** HS256, HS384, HS512

```javascript
// 共通鍵方式での署名生成・検証
const jwt = require('jsonwebtoken');

// 署名生成（認証サーバー）
const SECRET_KEY = process.env.JWT_SECRET; // 256bit以上の強固な秘密鍵
const token = jwt.sign(payload, SECRET_KEY, { algorithm: 'HS256' });

// 署名検証（APIサーバー）
// ※同じ秘密鍵が必要
try {
  const decoded = jwt.verify(token, SECRET_KEY, { algorithm: 'HS256' });
  console.log('検証成功:', decoded);
} catch (error) {
  console.log('検証失敗:', error.message);
}
```

**メリット:**
- 🚀 処理速度が高速（RSAの約10倍）
- 🔧 実装がシンプル
- 💾 メモリ使用量が少ない

**デメリット:**
- 🔑 全サーバーで秘密鍵を共有する必要
- 🔒 鍵漏洩時の影響範囲が広い
- 📦 マイクロサービス間での鍵管理が複雑

### 公開鍵方式（非対称暗号）- RSA/ECDSA

**特徴:**
- 署名生成に秘密鍵、検証に公開鍵を使用
- 鍵配布が安全
- 処理負荷が高い

**アルゴリズム:** RS256, RS384, RS512, ES256, ES384, ES512

```javascript
// 公開鍵方式での署名生成・検証
const jwt = require('jsonwebtoken');
const fs = require('fs');

// 鍵ペア準備
const PRIVATE_KEY = fs.readFileSync('private.pem');
const PUBLIC_KEY = fs.readFileSync('public.pem');

// 署名生成（認証サーバーのみ）
const token = jwt.sign(payload, PRIVATE_KEY, { 
  algorithm: 'RS256',
  keyid: 'key-1' // JWKSでの鍵識別用
});

// 署名検証（APIサーバー群）
// ※公開鍵のみで検証可能
try {
  const decoded = jwt.verify(token, PUBLIC_KEY, { algorithm: 'RS256' });
  console.log('検証成功:', decoded);
} catch (error) {
  console.log('検証失敗:', error.message);
}
```

**メリット:**
- 🔐 公開鍵のみでの検証（鍵漏洩リスク低）
- 🏗️ マイクロサービス向け（各サービスに公開鍵配布のみ）
- 🔄 鍵ローテーションが容易（JWKS対応）
- ✅ より高いセキュリティ

**デメリット:**
- 🐌 処理速度が遅い
- 🧮 CPU使用量が高い
- 🔧 実装と運用が複雑

### アーキテクチャ別の選択指針

| 構成 | 推奨方式 | 理由 |
|------|----------|------|
| モノリス | **共通鍵** | 1つのサーバーのため鍵管理が簡単、高速 |
| マイクロサービス | **公開鍵** | 各サービスに公開鍵配布、秘密鍵は認証サーバーのみ |
| CDN配信 | **公開鍵** | エッジサーバーでの検証が安全 |
| 高負荷API | **共通鍵** | パフォーマンス重視 |
| 金融・医療系 | **公開鍵** | セキュリティ要件が厳格 |

### JWKS（JSON Web Key Set）による鍵管理

**公開鍵方式での鍵配布の仕組み:**

```javascript
// 1. 認証サーバーがJWKSエンドポイントを公開
// GET https://auth.example.com/.well-known/jwks.json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-1",  // 鍵ID
      "use": "sig",    // 署名用
      "n": "0vx7agoebGcQSuuPiLJXZptN...",  // RSA公開鍵
      "e": "AQAB"
    }
  ]
}

// 2. APIサーバーが公開鍵を自動取得・検証
const jwksClient = require('jwks-rsa');

const client = jwksClient({
  jwksUri: 'https://auth.example.com/.well-known/jwks.json',
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 600000  // 10分キャッシュ
});

const getKey = (header, callback) => {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
};

// トークン検証時に自動で公開鍵を取得
jwt.verify(token, getKey, { algorithms: ['RS256'] });
```

### 署名検証の仕組み

```javascript
// サーバー側での検証プロセス
const verifyJWT = (token) => {
  const [headerB64, payloadB64, signatureB64] = token.split('.');
  
  // 1. ヘッダーとペイロードを再構築
  const expectedSignature = crypto
    .createHmac('sha256', SERVER_SECRET)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');
  
  // 2. 署名を比較（改ざんチェック）
  if (signatureB64 !== expectedSignature) {
    throw new Error('Invalid signature');
  }
  
  // 3. ペイロードをデコードしてクレームを確認
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
  
  // 4. 有効期限チェック
  if (payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expired');
  }
  
  return payload; // 検証済みのユーザー情報
};
```

### ステートレス認証の利点

- **水平スケーリング**: サーバー間でセッション共有不要
- **マイクロサービス対応**: サービス間で統一的な認証
- **CDN フレンドリー**: エッジでの認証判定が可能

## JWT のセキュリティリスクとOWASP対策

### 主要な脅威モデル（OWASP Top 10 準拠）

#### 1. トークン漏洩による認証バイパス
```javascript
// ❌ 危険: XSS でトークンが漏洩
localStorage.setItem('accessToken', token);

// ✅ 安全: メモリ保持 + HttpOnly Cookie
const [accessToken, setAccessToken] = useState(null);
document.cookie = `refreshToken=${token}; HttpOnly; Secure; SameSite=Strict`;
```

#### 2. アルゴリズム混乱攻撃 (Algorithm Confusion)

**攻撃の仕組み**: 攻撃者がJWTのヘッダーでアルゴリズムを`none`や`RS256`に変更し、署名検証をバイパスしようとする攻撃です。

```javascript
// ❌ 危険: ヘッダーのアルゴリズムをそのまま信用
const decoded = jwt.verify(token, secret); // ヘッダーの "alg" を使用

// 攻撃例: ヘッダーを {"alg": "none"} に変更されると署名検証がスキップされる
// または {"alg": "RS256"} に変更して公開鍵を悪用される

// ✅ 安全: アルゴリズムを明示的に指定
const decoded = jwt.verify(token, secret, { 
  algorithms: ['HS256'] // サーバー側で固定
});

// さらに安全な実装例
const verifySecurely = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],           // アルゴリズム固定
      issuer: 'auth.example.com',      // 発行者検証
      audience: 'api.example.com',     // 対象者検証
      maxAge: '15m'                    // 最大有効時間
    });
  } catch (error) {
    throw new Error(`JWT verification failed: ${error.message}`);
  }
};
```

### セキュリティ要件の定義

実務では以下の指標でセキュリティレベルを管理します：

- **RTO (Recovery Time Objective)**: トークン漏洩時の無効化時間 < 15分
  - *なぜ15分？*: アクセストークンの有効期限と同じ。漏洩してもこの時間で自動失効
- **RPO (Recovery Point Objective)**: セッションデータの最大損失時間 < 5分  
  - *実装方法*: リフレッシュトークンローテーションで古いトークンを即座に無効化
- **認可粒度**: リソースベースアクセス制御 (RBAC) + 属性ベースアクセス制御 (ABAC)
  - *RBAC*: `role: "admin"` でざっくり権限分け
  - *ABAC*: `permissions: ["user.read", "post.write"]` で細かい権限制御

## Token Rotation によるセキュリティ強化

### Access Token の設計パターン

```javascript
// JWT Payload 設計例（最小権限の原則）
{
  "sub": "user_123",
  "iss": "auth.yourapp.com",
  "aud": ["api.yourapp.com", "ws.yourapp.com"],
  "exp": Math.floor(Date.now() / 1000) + (15 * 60), // 15分
  "iat": Math.floor(Date.now() / 1000),
  "jti": "uuid-v4-token-id", // Replay Attack 防止
  "scope": "read:profile write:posts",
  "role": "user",
  "permissions": ["post.create", "comment.read"]
}
```

### Refresh Token Rotation の実装

**なぜローテーションが必要？**: リフレッシュトークンは長命なので、盗まれた場合のリスクが高い。使用の度に新しいトークンに交換することで、盗難時の被害を最小限に抑えます。

```javascript
// リフレッシュトークンローテーション
const refreshTokenRotation = async (currentRefreshToken) => {
  // 1. 現在のトークンを検証・無効化
  const tokenData = await verifyRefreshToken(currentRefreshToken);
  await revokeToken(currentRefreshToken); // 古いトークンを即座に使用不可に
  
  // 2. 新しいトークンペアを発行
  const newAccessToken = generateAccessToken(tokenData.user, 15 * 60);   // 15分
  const newRefreshToken = generateRefreshToken(tokenData.user, 7 * 24 * 60 * 60); // 7日
  
  // 3. トークンファミリー管理（Concurrent Refresh 対策）
  // 同時に複数のリフレッシュが実行された場合の対策
  await storeTokenFamily(tokenData.user.id, newRefreshToken, {
    parentToken: currentRefreshToken,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    // 使用済みトークンで再度リフレッシュされた場合、全トークンファミリーを無効化
    isRotated: true
  });
  
  return { accessToken: newAccessToken, refreshToken: newRefreshToken };
};

// Concurrent Refresh 攻撃への対策
const handleConcurrentRefresh = async (oldToken) => {
  const family = await getTokenFamily(oldToken);
  
  if (family && family.isRotated) {
    // 既に使用済みのトークンが再利用された = 攻撃の可能性
    await invalidateTokenFamily(family.userId); // 該当ユーザーの全トークンを無効化
    throw new Error('Token reuse detected - all sessions invalidated');
  }
};
```


## React における認証状態管理の最適化

### よくある質問: なぜコンテキストを使うのか？

Reactアプリでは複数のコンポーネントが認証状態を参照する必要があります。PropsDrillingを避け、グローバルに認証状態を管理するためにContextを使用します。

### 1. 認証コンテキストの設計

```typescript
interface AuthContextType {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<boolean>;
}

// シングルトンパターンで認証状態を管理
// なぜシングルトン？: アプリ全体で認証状態は1つだけ存在すべきだから
class AuthManager {
  private static instance: AuthManager;
  private accessToken: string | null = null;
  private refreshPromise: Promise<boolean> | null = null;
  
  static getInstance(): AuthManager {
    if (!AuthManager.instance) {
      AuthManager.instance = new AuthManager();
    }
    return AuthManager.instance;
  }
  
  async getValidToken(): Promise<string | null> {
    if (!this.accessToken) return null;
    
    // JWT の exp クレームをチェック（base64デコード）
    const payload = JSON.parse(atob(this.accessToken.split('.')[1]));
    const isExpired = payload.exp * 1000 < Date.now(); // UNIXタイムスタンプをミリ秒に変換
    
    if (isExpired) {
      // 同時リフレッシュを防ぐ（Race Condition対策）
      // 複数のAPIが同時に実行されても、リフレッシュは1回だけ
      if (!this.refreshPromise) {
        this.refreshPromise = this.refreshToken();
      }
      const success = await this.refreshPromise;
      this.refreshPromise = null;
      return success ? this.accessToken : null;
    }
    
    return this.accessToken;
  }
  
  // トークンの残り有効時間を取得（プロアクティブなリフレッシュ用）
  getTokenTimeRemaining(): number {
    if (!this.accessToken) return 0;
    
    const payload = JSON.parse(atob(this.accessToken.split('.')[1]));
    const expirationTime = payload.exp * 1000;
    const currentTime = Date.now();
    
    return Math.max(0, expirationTime - currentTime);
  }
}
```


## HTTP インターセプターによるトークン管理

### Axios インターセプターの実装

```typescript
// api/client.ts
import axios, { AxiosError, AxiosRequestConfig } from 'axios';

class ApiClient {
  private client = axios.create({
    baseURL: process.env.NEXT_PUBLIC_API_BASE_URL,
    withCredentials: true, // HttpOnly Cookie を含める
  });

  constructor(private authManager: AuthManager) {
    this.setupInterceptors();
  }

  private setupInterceptors() {
    // Request インターセプター: 自動でトークン付与
    this.client.interceptors.request.use(async (config) => {
      const token = await this.authManager.getValidToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Response インターセプター: 401 時の自動リトライ
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };
        
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;
          
          const refreshed = await this.authManager.refreshToken();
          if (refreshed) {
            const token = await this.authManager.getValidToken();
            originalRequest.headers!.Authorization = `Bearer ${token}`;
            return this.client(originalRequest);
          } else {
            // リフレッシュ失敗時はログアウト
            this.authManager.logout();
            window.location.href = '/login';
          }
        }
        
        return Promise.reject(error);
      }
    );
  }
}
```


## 認証フローを図で理解

```
1. ログイン
[ログイン画面] --(ID/PW)--> [サーバー]
                                |
                                v
                    アクセストークン（メモリ保存）
                    + リフレッシュトークン（Cookie保存）

2. API呼び出し
[React App] --アクセストークン--> [API] → 成功！

3. トークン期限切れ時の自動更新
[React App] --期限切れトークン--> [API] → 401エラー
     |
     v 自動的に
[リフレッシュ要求] --Cookie--> [サーバー]
     |                           |
     v                           v
新しいアクセストークンを取得 → 元のAPIを再実行
```


## 実際の認証状態の変化

### ログイン前（未認証状態）
```
📱 React の状態:
  - isAuthenticated: false
  - accessToken: null
  - user: null

👤 ユーザーが見える画面:
  - ログインフォーム
  - 「会員登録」ボタン
  - 公開ページのみアクセス可能
```

### ログイン後（認証状態）
```
📱 React の状態:
  - isAuthenticated: true
  - accessToken: "eyJhbGciOiJIUzI1NiIs..." (メモリ上)
  - user: { id: 123, name: "田中太郎", email: "..." }

🍪 ブラウザのCookie:
  - refreshToken: "abc123..." (HttpOnly)

👤 ユーザーが見える画面:
  - マイページ
  - 設定画面
  - ログアウトボタン
```

### トークン期限切れ時（自動復旧）
```
📱 React の動作:
  1. APIから401エラーを受信
  2. 「あ、トークンが期限切れだ」
  3. リフレッシュAPIを自動呼び出し
  4. 新しいトークンで元の処理を再実行

👤 ユーザーの体験:
  - 何も気づかない（裏で自動処理）
  - 再ログインは不要
```


## Cookieの設計（サーバ設定だがフロントも前提化）

- `HttpOnly`：JSから読めない（**必須**）
- `Secure`：HTTPSのみ送信（**本番必須**）
- `SameSite`：  
  - 可能なら `Lax` / `Strict`（CSRF耐性）  
  - クロスサイト必須なら `None; Secure` にして**CSRF対策を強める**
- `Path` / `Domain` を絞る（例：`Path=/auth`）
- **フロントは Cookie 値を直接扱わない設計**にする


## CSRF対策（Cookie使用時は必須）

- **SameSite** を適切に（`Lax`/`Strict` 推奨）  
- クロスサイトが必要な場合：  
  - **Double Submit Token**（CookieにCSRF値 & ヘッダに同値）  
  - **Origin/Referer 検証**（TLS下）  
- **状態変更系**は**POST/PUT/PATCH/DELETE**＋CSRFチェック
- **GETは副作用を持たせない**


## CORSの正しい前提

- フロント：`credentials: 'include'`（または axios `withCredentials: true`）
- サーバ：`Access-Control-Allow-Credentials: true`
- `Access-Control-Allow-Origin: *` は **Cookie併用時NG**  
  → 具体的なオリジンを許可（必要なら複数を明示的に）
- キャッシュ汚染回避に `Vary: Origin`


## なぜアクセストークンはメモリに保存？

### ❌ localStorage / sessionStorage は危険
- **XSS攻撃**でJavaScriptから簡単に読み取られる
- 悪意あるスクリプトがトークンを盗んで送信

### ⭕ メモリ保存が安全
- **XSS攻撃**からも比較的安全
- ページをリロードすると消える → セキュリティ向上

### UXの心配は不要
- リロード時は**自動でリフレッシュトークンから復旧**
- ユーザーは再ログインする必要なし


## React でのユーザー体験の作り方

### アプリ起動時の挙動
```
👤 ユーザー: ブラウザでサイトを開く
📱 React: 
  1. 「認証状態を確認中...」を表示
  2. リフレッシュトークンでサイレント認証を試行
  3-A. 成功 → メイン画面を表示
  3-B. 失敗 → ログイン画面を表示
```

### ページアクセス制御の実装
```
✅ 誰でも見られるページ
  - トップページ
  - 会社概要
  - ログイン/会員登録

🔒 ログインが必要なページ
  - マイページ
  - 設定画面
  - 管理画面
```

### エラー時のユーザー体験
```
😕 よくないパターン:
  「401 Unauthorized」→ 突然ログイン画面

😊 良いパターン:
  「セッションの期限が切れました。自動で更新しています...」
  → 成功: そのまま続行
  → 失敗: 「再度ログインしてください」
```


## Next.js での注意（SSR）

- **アクセストークンはクライアント専用**（SSRで注入しない）  
- SSRでユーザ情報が必要なとき：  
  - API Route（サーバ側）でCookie→バックエンドに**サーバ間通信**  
  - ページへは**最小の安全データ**のみ返す（トークン自体は返さない）
- ルート保護・リダイレクトは**クライアント判定**を基本に


## 失効とセキュリティ強化

- **リフレッシュトークンのローテーション**（使い捨て・前回の無効化）
- デバイス/セッション一覧と**強制ログアウト**
- **CSP（Content-Security-Policy）**でXSS面を縮小
- 短い`exp`・スコープ最小化・監査ログ
- MFA/2FA の導入


## 初心者がハマりやすい罠

### 🚫 やってはいけないこと
1. **localStorage にトークン保存** 
   - XSS攻撃で簡単に盗まれる
2. **長すぎるトークン有効期限**
   - 被害が拡大する可能性
3. **HTTPS を使わない**
   - 通信を盗聴される

### ⚠️ 設定ミス例
- Cookie設定で `Secure` フラグを付け忘れ
- CORS で `*` を使いながら認証情報も送信
- 複数のリフレッシュ要求が同時実行される


## 品質チェックリスト

- [ ] アクセストークン：**メモリのみ**保持（短命）  
- [ ] リフレッシュ：**HttpOnly + Secure Cookie**  
- [ ] 起動時サイレントリフレッシュ／401時自動リフレッシュ  
- [ ] CSRF：SameSite / Double Submit / Origin検証  
- [ ] CORS：特定オリジン + `Allow-Credentials`  
- [ ] ログアウト：サーバ失効 + Cookie削除 + クライアント状態破棄  
- [ ] 監査ログ・ローテーション・CSP・MFA


## まとめ

- **JWT認証** = 署名検証でスケールするステートレス認可
- **フロントの鉄則**：  
  - アクセスは**メモリ保持**  
  - リフレッシュは**HttpOnly Cookie**  
  - 401→**自動リフレッシュ**→失敗時ログアウト  
  - CSRF/CORS/HTTPSを**前提化**
- この設計で「安全性」と「使い勝手」を両立


## 付録：用語の最短リファレンス

- **JWT**：署名付きクレームの集合（`header.payload.signature`）  
- **Bearer**：持っているだけで権利を示すトークン  
- **HttpOnly**：JSから読み取れないCookie属性  
- **SameSite**：クロスサイト送信の制御（`Lax/Strict/None`）  
- **CSRF**：利用者の意図しないリクエストの強要  
- **CSP**：実行元を制限してXSSを緩和するヘッダ


## 実装時の心構え

### 🎯 覚えておくべき核心
1. **アクセストークンは短命でメモリ保存**
2. **リフレッシュトークンは長命でHttpOnly Cookie**
3. **401エラー時は自動でリフレッシュを試行**
4. **ユーザーには認証処理を意識させない**

### 📚 次のステップ
- 実際のコード実装（useAuth フック、API インターセプター）
- セキュリティテスト（XSS、CSRF対策の検証）
- ユーザビリティテスト（認証フローの改善）


## HTTP Cookie の仕組みと実装パターン

### よくある質問: Cookie と localStorage の違いは？

| 特徴 | Cookie | localStorage |
|------|--------|-------------|
| 容量制限 | 4KB | 5-10MB |
| 自動送信 | ✅ すべてのリクエストで自動 | ❌ JavaScriptで手動 |
| XSS耐性 | ✅ HttpOnlyなら安全 | ❌ JS から読み取り可能 |
| 有効期限 | ✅ Max-Age で自動削除 | ❌ 手動削除が必要 |
| 用途 | 認証情報、設定 | アプリの状態、キャッシュ |

### Cookie の基本動作フロー

```
1. サーバー → ブラウザ: Set-Cookie ヘッダーで値を送信
   HTTP/1.1 200 OK
   Set-Cookie: sessionId=abc123; HttpOnly; Secure; SameSite=Lax
   Set-Cookie: theme=dark; Path=/; Max-Age=86400

2. ブラウザ: Cookie を自動保存（ブラウザの専用ストレージに保存）
   - Chrome: C:\Users\[user]\AppData\Local\Google\Chrome\User Data\Default\Cookies
   - Firefox: ~/.mozilla/firefox/[profile]/cookies.sqlite

3. ブラウザ → サーバー: 以降のリクエストで自動送信
   GET /api/user HTTP/1.1
   Cookie: sessionId=abc123; theme=dark
   ↑ブラウザが自動で付与（JavaScriptコード不要）

4. サーバー: Cookie を解析してユーザー状態を復元
   const cookies = parseCookies(req.headers.cookie);
   const sessionId = cookies.sessionId; // "abc123"
```

### Cookie 属性の詳細解説

```typescript
interface CookieOptions {
  // セキュリティ関連
  httpOnly: boolean;    // JavaScript からアクセス不可
  secure: boolean;      // HTTPS でのみ送信
  sameSite: 'strict' | 'lax' | 'none'; // CSRF 対策
  
  // スコープ関連
  domain: string;       // 有効ドメイン (.example.com)
  path: string;         // 有効パス (/api/)
  
  // 生存期間関連
  maxAge: number;       // 秒単位の生存期間
  expires: Date;        // 絶対的な期限日時
}

// 実装例：セキュアなセッション Cookie
const setSessionCookie = (res: Response, sessionId: string) => {
  const cookieValue = `sessionId=${sessionId}`;
  const options = [
    'HttpOnly',                    // XSS 攻撃防止
    'Secure',                     // HTTPS 必須
    'SameSite=Strict',            // CSRF 攻撃防止
    `Path=${COOKIE_PATH}`,        // スコープ制限
    `Domain=${COOKIE_DOMAIN}`,    // サブドメイン制御
    `Max-Age=${7 * 24 * 60 * 60}` // 7日間
  ].join('; ');
  
  res.setHeader('Set-Cookie', `${cookieValue}; ${options}`);
};
```


## セッション管理の実装アーキテクチャ

### 1. インメモリセッション（開発・小規模）

```typescript
class InMemorySessionStore {
  private sessions = new Map<string, SessionData>();
  
  async create(userId: string, data: any): Promise<string> {
    const sessionId = crypto.randomUUID();
    this.sessions.set(sessionId, {
      userId,
      data,
      createdAt: new Date(),
      lastAccessed: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24時間
    });
    return sessionId;
  }
  
  async get(sessionId: string): Promise<SessionData | null> {
    const session = this.sessions.get(sessionId);
    if (!session || session.expiresAt < new Date()) {
      this.sessions.delete(sessionId);
      return null;
    }
    
    // アクセス時間更新
    session.lastAccessed = new Date();
    return session;
  }
  
  async destroy(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }
  
  // ガベージコレクション（期限切れセッションの削除）
  private cleanup() {
    const now = new Date();
    for (const [id, session] of this.sessions) {
      if (session.expiresAt < now) {
        this.sessions.delete(id);
      }
    }
  }
}
```

### 2. Redis セッション（本番・大規模）

```typescript
class RedisSessionStore {
  private redis: Redis;
  
  constructor(redisUrl: string) {
    this.redis = new Redis(redisUrl);
  }
  
  async create(userId: string, data: any): Promise<string> {
    const sessionId = `sess:${crypto.randomUUID()}`;
    const sessionData = {
      userId,
      data,
      createdAt: Date.now(),
      lastAccessed: Date.now()
    };
    
    // Redis に保存（TTL付き）
    await this.redis.setex(
      sessionId, 
      24 * 60 * 60, // 24時間TTL
      JSON.stringify(sessionData)
    );
    
    return sessionId;
  }
  
  async get(sessionId: string): Promise<SessionData | null> {
    const data = await this.redis.get(sessionId);
    if (!data) return null;
    
    const session = JSON.parse(data);
    
    // アクセス時間更新 + TTL延長
    session.lastAccessed = Date.now();
    await this.redis.setex(
      sessionId,
      24 * 60 * 60,
      JSON.stringify(session)
    );
    
    return session;
  }
  
  async destroy(sessionId: string): Promise<void> {
    await this.redis.del(sessionId);
  }
  
  // ユーザーの全セッション削除（強制ログアウト）
  async destroyUserSessions(userId: string): Promise<void> {
    const pattern = 'sess:*';
    const keys = await this.redis.keys(pattern);
    
    for (const key of keys) {
      const data = await this.redis.get(key);
      if (data) {
        const session = JSON.parse(data);
        if (session.userId === userId) {
          await this.redis.del(key);
        }
      }
    }
  }
}
```


## セッション vs JWT の技術的比較

### データフロー比較

```typescript
// セッションベース認証のフロー
class SessionAuth {
  async authenticate(req: Request): Promise<User | null> {
    const sessionId = this.extractSessionId(req); // Cookie から取得
    if (!sessionId) return null;
    
    // 毎回データベース/Redis にアクセス
    const sessionData = await this.sessionStore.get(sessionId);
    if (!sessionData) return null;
    
    // ユーザー情報を取得
    return await this.userRepository.findById(sessionData.userId);
  }
}

// JWT ベース認証のフロー
class JWTAuth {
  async authenticate(req: Request): Promise<User | null> {
    const token = this.extractToken(req); // Authorization ヘッダーから取得
    if (!token) return null;
    
    try {
      // 署名検証のみ（データベースアクセス不要）
      const payload = jwt.verify(token, this.secret, {
        algorithms: ['HS256'],
        issuer: 'auth.example.com',
        audience: 'api.example.com'
      });
      
      // ペイロードから直接ユーザー情報を取得
      return {
        id: payload.sub,
        email: payload.email,
        role: payload.role,
        permissions: payload.permissions
      };
    } catch (error) {
      return null;
    }
  }
}
```

### パフォーマンス・スケーラビリティ比較

**実測データに基づく比較** (Express.js + Redis/JWT での検証結果)

```typescript
// ベンチマーク結果例
interface AuthPerformance {
  method: 'session' | 'jwt';
  requestsPerSecond: number;
  avgLatency: number;
  dbConnections: number;
  memoryUsage: string;
}

const performanceComparison: AuthPerformance[] = [
  {
    method: 'session',
    requestsPerSecond: 5000,   // Redis アクセスがボトルネック
    avgLatency: 15,           // ms (Redis往復時間含む)
    dbConnections: 100,       // Redis 接続プール
    memoryUsage: '50MB'       // セッションデータ保存
  },
  {
    method: 'jwt',
    requestsPerSecond: 25000,  // CPU のみの処理（署名検証）
    avgLatency: 3,            // ms (メモリ内処理のみ)
    dbConnections: 0,         // データベースアクセス不要
    memoryUsage: '10MB'       // JWTライブラリのみ
  }
];

// スケーラビリティの考慮点
class ScalabilityConsiderations {
  // セッション方式：水平スケーリング時の課題
  sessionChallenges() {
    return [
      'Redis の単一障害点（マスター/スレーブ構成が必要）',
      'セッションデータの複製コスト（レプリケーション遅延）',
      'ネットワーク I/O による遅延（特に高トラフィック時）',
      'Redis クラスタの運用コスト（監視・メンテナンス）'
    ];
  }
  
  // JWT方式：水平スケーリング時の利点
  jwtBenefits() {
    return [
      'ステートレス（サーバー間の状態共有不要）',
      'CDN でのエッジ認証が可能（CloudFlare Workers等）',
      'マイクロサービス間での認証情報共有が容易',
      'データベース負荷の軽減（DB接続プール不要）',
      'Auto Scaling 時の即座対応（ウォームアップ不要）'
    ];
  }
  
  // トレードオフの判断基準
  getRecommendation(userCount: number, requestsPerSecond: number) {
    if (requestsPerSecond > 10000 || userCount > 100000) {
      return 'JWT推奨: 高負荷・大規模サービス向け';
    } else if (userCount < 1000) {
      return 'セッション推奨: 小規模・管理重視';
    } else {
      return 'ハイブリッド推奨: JWT(API) + セッション(管理)';
    }
  }
}
```


## Cookie セキュリティとブラウザ互換性

### 環境別 Cookie 設定の最適化

```typescript
// 環境別 Cookie 設定の最適化
const setCookieOptions = (env = process.env.NODE_ENV) => {
  const baseOptions = {
    httpOnly: true,
    path: '/',
    maxAge: 7 * 24 * 60 * 60, // 7日間
  };

  switch (env) {
    case 'development':
      return {
        ...baseOptions,
        secure: false,
        sameSite: 'lax' as const, // localhost での開発用
      };
    case 'staging':
      return {
        ...baseOptions,
        secure: true,
        sameSite: 'none' as const, // クロスオリジンテスト用
        domain: '.staging.example.com',
      };
    case 'production':
      return {
        ...baseOptions,
        secure: true,
        sameSite: 'strict' as const, // 最高のセキュリティ
        domain: '.example.com',
      };
  }
};

// ブラウザ互換性を考慮した Cookie 設定
const setSecureCookie = (res: Response, name: string, value: string, options: CookieOptions) => {
  const userAgent = res.req.headers['user-agent'] || '';
  const isChrome80Plus = /Chrome\/([8-9][0-9]|[1-9][0-9]{2,})/.test(userAgent);
  
  // Chrome 80+ の SameSite=None 対応
  if (isChrome80Plus && options.sameSite === 'none') {
    options.secure = true;
  }
  
  res.setHeader('Set-Cookie', serialize(name, value, options));
};
```

### 2つの認証方式の比較（どっちがいいの？）

#### 従来のセッション認証：「会員証方式」
```
🎫 図書館の会員証のような仕組み
1. ログイン → 「会員証番号123」を発行
2. 本を借りる時 → 会員証を提示
3. 図書館員 → 台帳で「123番は田中さんだ」と確認
4. 本を貸し出し

✅ いいところ：
- 会員証を紛失したら即座に無効化できる
- 図書館が完全にコントロール

😅 大変なところ：
- 毎回台帳を確認する手間
- 支店が増えると台帳の共有が大変
```

#### JWT認証：「身分証明書方式」
```
🪪 運転免許証のような仕組み
1. ログイン → 「本人情報入りの身分証」を発行
2. 本を借りる時 → 身分証を提示
3. 図書館員 → 身分証を見るだけで本人確認完了
4. 本を貸し出し

✅ いいところ：
- 台帳確認が不要（スピーディー）
- 支店が増えても同じ身分証で OK

😅 大変なところ：
- 紛失してもすぐには無効化できない
- 身分証の内容は後から変更不可
```


## Cookie のセキュリティ設定（安全な付箋メモにする方法）

### Cookie に付ける「安全シール」の種類

**HttpOnly シール**
```
🔒 このシールが付いていると...
✅ 悪意のあるプログラムから見えなくなる
❌ シールなし = プログラムに丸見え（危険！）

🏠 例え話：
- HttpOnly あり = 金庫の中の重要書類
- HttpOnly なし = 机の上の重要書類（誰でも見れる）
```

**Secure シール**
```
🌐 このシールが付いていると...
✅ 暗号化された通信（HTTPS）でのみ送信
❌ シールなし = 暗号化なし通信でも送信（盗聴される）

📞 例え話：
- Secure あり = 暗号化された電話
- Secure なし = 普通の電話（盗聴可能）
```

**SameSite シール**
```
🛡️ このシールは「どこからのアクセスを許可するか」を決める

🔒 Strict（厳格）: 同じサイト内でのみ使用
⚖️ Lax（適度）: 普通のリンクはOK、怪しいフォームはNG
🌐 None（なんでも）: どこからでもOK（危険だが時々必要）

🏪 例え話：
- Strict = 会員のみ入店可能
- Lax = 一見さんもOKだが、怪しい人はお断り  
- None = 誰でも入店OK
```


## どちらを選ぶべき？（用途別ガイド）

### セッション認証（会員証方式）が向いている場面
```
🏢 社内システム・管理画面
👥 社員20人の会社の勤怠管理システム
💭 理由：「あの人をすぐにログアウトさせたい」ができる

🛒 ショッピングサイト
💳 Amazon や楽天のようなECサイト
💭 理由：不正な購入を発見したら即座に止められる

🏥 病院・銀行システム
💰 お金や個人情報を扱う重要なシステム
💭 理由：セキュリティを最優先にしたい
```

### JWT認証（身分証方式）が向いている場面
```
📱 スマホアプリ + Webサービス
📲 InstagramやTwitterのような大規模アプリ
💭 理由：世界中のサーバーで同じ認証が使える

🎮 ゲーム・エンタメサービス
🎯 ゲームのスコアやプロフィール管理
💭 理由：サーバーの負荷を下げてスムーズに動作

🌍 複数のサービス連携
🔗 Google、Facebook、LINE ログイン
💭 理由：一つの身分証で色々なサービスが使える
```


## ハイブリッド構成：JWT + セッション

### 実際のプロダクトでよく使われるパターン

```
🎯 ベストプラクティス：

1. 短命JWT（アクセストークン）: API呼び出し用
2. セッション管理（リフレッシュトークン）: 長期認証用

メリット：
✅ APIはJWTでステートレス（高速・スケーラブル）
✅ 認証管理はセッションで柔軟性（即座無効化可能）
✅ セキュリティと利便性の両立
```

#### 具体的な設計例
```javascript
// ログイン時
const login = async () => {
  // 1. ユーザー認証
  const user = await authenticateUser(email, password);
  
  // 2. セッション作成（データベースに保存）
  const sessionId = await createSession(user.id);
  
  // 3. JWT作成（短命・ユーザー情報含む）
  const accessToken = generateJWT(user, '15m');
  
  // 4. セッションIDをHttpOnly Cookieに保存
  res.setHeader('Set-Cookie', [
    `sessionId=${sessionId}; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
  ]);
  
  // 5. アクセストークンをレスポンスで返す
  res.json({ accessToken, user });
};

// リフレッシュ時
const refresh = async () => {
  const { sessionId } = req.cookies;
  
  // セッションの有効性をデータベースで確認
  const session = await getValidSession(sessionId);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  
  // 新しいJWTを発行
  const user = await getUserById(session.userId);
  const newAccessToken = generateJWT(user, '15m');
  
  res.json({ accessToken: newAccessToken, user });
};

// 強制ログアウト（管理者機能）
const forceLogout = async (userId) => {
  // データベースのセッションを無効化
  await invalidateUserSessions(userId);
  // 次回リフレッシュ時に認証エラーになる
};
```


## Cookie の実装パターンとトラブル対処

### よくある Cookie の問題

#### 1. ローカル開発でのCookie問題
```javascript
// ❌ 本番では動くが、localhost:3000 では動かない
res.setHeader('Set-Cookie', [
  'token=abc; Secure; SameSite=None'
]);

// ✅ 開発環境での対処
const isDev = process.env.NODE_ENV === 'development';
res.setHeader('Set-Cookie', [
  `token=abc; ${isDev ? '' : 'Secure;'} SameSite=${isDev ? 'Lax' : 'None'}`
]);
```

#### 2. CORS でのCookie送信
```javascript
// フロントエンド（React）
fetch('/api/data', {
  credentials: 'include' // Cookie を送信するために必須
});

// バックエンド（Express）
app.use(cors({
  origin: 'http://localhost:3000', // 具体的なオリジンを指定
  credentials: true // Cookie を受け入れる
}));

// ❌ これはNG
app.use(cors({
  origin: '*',        // ワイルドカードと
  credentials: true   // credentials は併用不可
}));
```

#### 3. Cookie サイズ制限
```
📏 制限：
- 1つのCookie: 4KB以下
- 1つのドメイン: 300個まで
- ブラウザ全体: 3000個まで

💡 対処法：
- JWTが大きくなりすぎる場合はペイロード縮小
- 複数Cookieに分割
- セッションIDのみCookieに保存し、データはサーバー側で管理
```


## ハッカーからサイトを守る方法

### 主な攻撃パターンと対策

#### 1. XSS攻撃：「偽の看板を貼り付ける」攻撃

**🚨 どんな攻撃？**
```
🎭 詐欺師の手口
1. あなたのサイトに偽のポップアップを表示
2. 「セキュリティ確認のためパスワードを入力してください」
3. ユーザーが騙されて入力
4. パスワードが盗まれる

💻 技術的には...
悪意のあるプログラムがサイトに紛れ込んで
ログイン情報を盗み取る
```

**🛡️ 対策**
```javascript
// ❌ 危険：localStorage にトークン保存
localStorage.setItem('token', accessToken);

// ✅ 安全：メモリのみに保存
const [accessToken, setAccessToken] = useState(null);

// ✅ 入力値のサニタイズ
const sanitizeInput = (input) => {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
};

// ✅ CSP (Content Security Policy) ヘッダー設定
// Next.js の next.config.js
const nextConfig = {
  async headers() {
    return [{
      source: '/(.*)',
      headers: [
        {
          key: 'Content-Security-Policy',
          value: "script-src 'self' 'unsafe-eval'; object-src 'none';"
        }
      ]
    }];
  }
};
```


#### 2. CSRF攻撃：「なりすまし操作」攻撃

**🚨 どんな攻撃？**
```
🎯 巧妙な罠
1. あなたは銀行サイトにログイン済み
2. 悪意のあるサイトで「可愛い猫の写真を見る」ボタンをクリック
3. 実は裏でこっそり「100万円振り込み」が実行される
4. ブラウザが「ログイン中だから本人の操作だ」と勘違い
5. お金が盗まれる

🏠 例え話
玄関の鍵を開けっ放しにしていたら
知らない間に家の中のものを勝手に使われた
```

**🛡️ 対策1: SameSite Cookie**
```javascript
// サーバーでの設定
res.setHeader('Set-Cookie', [
  `refreshToken=${token}; HttpOnly; Secure; SameSite=Strict; Path=/`
]);

// SameSite の種類
// Strict: 同一サイトからのリクエストのみ
// Lax: 通常のリンクは許可、フォーム送信は制限
// None: すべて許可（Secure必須）
```

**🛡️ 対策2: CSRF トークン（Double Submit Cookie）**
```javascript
// サーバー側：CSRFトークン生成・送信
const csrfToken = generateRandomToken();

// Cookie にも設定
res.setHeader('Set-Cookie', [
  `csrfToken=${csrfToken}; SameSite=Strict`,
  `refreshToken=${refreshToken}; HttpOnly; SameSite=Strict`
]);

// レスポンスにも含める
res.json({ accessToken, csrfToken, user });

// React 側：CSRFトークンをヘッダーに付与
const apiCall = async (url, options = {}) => {
  const csrfToken = getCsrfTokenFromCookie();
  
  return fetch(url, {
    ...options,
    headers: {
      'X-CSRF-Token': csrfToken,
      'Content-Type': 'application/json',
      ...options.headers
    },
    credentials: 'include'
  });
};

// サーバー側：CSRF トークン検証
const verifyCsrfToken = (req, res, next) => {
  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies.csrfToken;
  
  if (!headerToken || !cookieToken || headerToken !== cookieToken) {
    return res.status(403).json({ error: 'CSRF token mismatch' });
  }
  
  next();
};
```


#### 3. セッション固定攻撃：「合鍵をすり替える」攻撃

**🚨 どんな攻撃？**
```
🗝️ 巧妙なすり替え
1. 攻撃者：「この合鍵を使ってね」と偽の鍵を渡す
2. あなた：その鍵でログイン
3. あなた：「正常にログインできた」と安心
4. 攻撃者：実は同じ鍵を持っているので、いつでも侵入可能
5. 攻撃者：あなたのフリをしてサイトを使い放題

🏨 例え話
ホテルで「お部屋の鍵を交換します」と言われ
実は攻撃者も同じ鍵を持っていた
```

**🛡️ 対策：セッションの再生成**
```javascript
// ログイン成功時：新しいセッションIDを生成
const login = async (email, password) => {
  const user = await authenticateUser(email, password);
  
  if (user) {
    // 古いセッションを無効化
    await invalidateSession(req.sessionId);
    
    // 新しいセッション作成
    const newSessionId = await createNewSession(user.id);
    
    // 新しいCookieを設定
    res.setHeader('Set-Cookie', [
      `sessionId=${newSessionId}; HttpOnly; Secure; SameSite=Strict`
    ]);
  }
};
```


## 実践的なセキュリティ実装

### 1. 強化されたAPI クライアント

```javascript
// utils/secureApiClient.js
class SecureApiClient {
  constructor() {
    this.accessToken = null;
    this.csrfToken = null;
  }

  // CSRFトークンの取得
  getCsrfToken() {
    const cookies = document.cookie.split(';');
    const csrfCookie = cookies.find(cookie => 
      cookie.trim().startsWith('csrfToken=')
    );
    return csrfCookie ? csrfCookie.split('=')[1] : null;
  }

  // セキュアなリクエスト
  async secureRequest(url, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    // JWTアクセストークンを付与
    if (this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    // CSRFトークンを付与（状態変更系のリクエスト）
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method)) {
      const csrfToken = this.getCsrfToken();
      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }
    }

    let response = await fetch(url, {
      ...options,
      headers,
      credentials: 'include' // Cookie自動送信
    });

    // 401エラー時の自動リフレッシュ
    if (response.status === 401) {
      const refreshed = await this.refreshTokens();
      if (refreshed) {
        // リトライ
        headers['Authorization'] = `Bearer ${this.accessToken}`;
        response = await fetch(url, { ...options, headers, credentials: 'include' });
      }
    }

    return response;
  }

  // トークンリフレッシュ（CSRFトークンも更新）
  async refreshTokens() {
    try {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'include'
      });

      if (response.ok) {
        const data = await response.json();
        this.accessToken = data.accessToken;
        this.csrfToken = data.csrfToken; // 新しいCSRFトークンも受信
        return true;
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
    }
    return false;
  }
}

export const apiClient = new SecureApiClient();
```


### 2. セキュリティミドルウェア

```javascript
// middleware/security.js

// レート制限
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15分
  max: 5, // 最大5回の試行
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false
});

// CSRF保護
const csrfProtection = (req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const headerToken = req.headers['x-csrf-token'];
    const cookieToken = req.cookies.csrfToken;
    
    if (!headerToken || headerToken !== cookieToken) {
      return res.status(403).json({ 
        error: 'Invalid CSRF token' 
      });
    }
  }
  next();
};

// セキュリティヘッダー
const securityHeaders = (req, res, next) => {
  // XSS保護
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // HTTPS強制
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  // CSP
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
  );
  
  next();
};

// 使用例
app.use(securityHeaders);
app.use('/api/auth/login', loginLimiter);
app.use('/api', csrfProtection);
```


### 3. 入力検証とサニタイズ

```javascript
// utils/validation.js
import DOMPurify from 'isomorphic-dompurify';

// 入力値の検証
export const validateInput = {
  email: (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  },
  
  password: (password) => {
    // 最小8文字、大文字・小文字・数字・記号を含む
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
  },
  
  username: (username) => {
    // 3-20文字、英数字とアンダースコアのみ
    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    return usernameRegex.test(username);
  }
};

// HTMLサニタイズ
export const sanitizeHtml = (dirty) => {
  return DOMPurify.sanitize(dirty);
};

// SQLインジェクション対策（パラメータ化クエリ）
// ❌ 危険
const query = `SELECT * FROM users WHERE email = '${email}'`;

// ✅ 安全
const query = 'SELECT * FROM users WHERE email = ?';
const result = await db.query(query, [email]);
```


### 4. ログ監視とアラート

```javascript
// utils/securityLogger.js
export const securityLogger = {
  // 怪しい活動をログ記録
  logSuspiciousActivity: (event, details) => {
    console.warn('🚨 Security Alert:', {
      timestamp: new Date().toISOString(),
      event,
      ip: details.ip,
      userAgent: details.userAgent,
      userId: details.userId,
      details
    });
    
    // 外部監視サービスに送信
    // sendToSecurityService(event, details);
  },

  // ログイン試行の監視
  logLoginAttempt: (email, success, ip, userAgent) => {
    const event = success ? 'login_success' : 'login_failure';
    
    if (!success) {
      securityLogger.logSuspiciousActivity('failed_login', {
        email, ip, userAgent
      });
    }
  },

  // 異常なAPI呼び出しを検知
  detectAnomalousRequests: (req) => {
    const suspiciousPatterns = [
      /script/i,
      /javascript/i,
      /<script>/i,
      /SELECT.*FROM/i,
      /UNION.*SELECT/i
    ];

    const requestData = JSON.stringify(req.body);
    
    suspiciousPatterns.forEach(pattern => {
      if (pattern.test(requestData)) {
        securityLogger.logSuspiciousActivity('potential_injection', {
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          requestBody: req.body,
          pattern: pattern.toString()
        });
      }
    });
  }
};

// 使用例
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  // 異常パターンを検知
  securityLogger.detectAnomalousRequests(req);
  
  const user = authenticateUser(email, password);
  
  // ログイン試行を記録
  securityLogger.logLoginAttempt(
    email, 
    !!user, 
    req.ip, 
    req.headers['user-agent']
  );
  
  if (user) {
    // ログイン成功処理
  } else {
    res.status(401).json({ error: 'Authentication failed' });
  }
});
```


### 5. 安全なサイトを作るチェックリスト

#### 🔒 ログイン機能の安全性
- [ ] パスワードは暗号化して保存（生のまま保存しない）
- [ ] ログイン状態は15分で期限切れ
- [ ] 更新用トークンはブラウザの安全な場所に保存
- [ ] ログインの度に新しい認証情報を発行

#### 🛡️ 悪意のあるプログラム対策（XSS）
- [ ] ユーザーの入力をそのまま表示しない（危険文字の除去）
- [ ] セキュリティポリシーの設定
- [ ] ログイン情報をブラウザのローカル保存に置かない
- [ ] 安全なデータ表示方法を使う

#### 🚫 なりすまし操作対策（CSRF）
- [ ] Cookie に「同サイトのみ」設定
- [ ] 本人確認トークンの実装
- [ ] リクエスト元の確認
- [ ] 重要な操作は POST リクエストのみ

#### 🌐 通信の安全性
- [ ] HTTPS（暗号化通信）の強制
- [ ] Cookie に「暗号化通信のみ」フラグ
- [ ] ブラウザにHTTPS強制を指示
- [ ] 外部サイトとの連携設定を適切に

#### 📊 異常の監視・記録
- [ ] ログイン失敗の回数を監視
- [ ] 短時間の大量アクセスを制限
- [ ] 怪しいリクエストパターンを検知
- [ ] セキュリティ問題が起きたらアラート


## 実装例：Next.js/React での JWT 認証

### 1. 認証状態の管理（Context）

```javascript
// contexts/AuthContext.js
const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(null); // メモリのみ
  const [loading, setLoading] = useState(true);

  // アプリ起動時：サイレントリフレッシュを試行
  useEffect(() => {
    const initAuth = async () => {
      try {
        // Cookie のリフレッシュトークンで認証状態を復旧
        const response = await fetch('/api/auth/refresh', {
          credentials: 'include' // Cookie を自動送信
        });
        
        if (response.ok) {
          const data = await response.json();
          setAccessToken(data.accessToken); // メモリに保存
          setUser(data.user);
          setIsAuthenticated(true);
        }
      } catch (error) {
        console.log('認証状態の復旧に失敗');
      } finally {
        setLoading(false);
      }
    };
    
    initAuth();
  }, []);
```


### 2. ログイン処理の実装

```javascript
  // ログイン関数
  const login = async (email, password) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // Cookie を受け取るため
        body: JSON.stringify({ email, password })
      });

      if (response.ok) {
        const data = await response.json();
        
        // アクセストークンはメモリのみに保存
        setAccessToken(data.accessToken);
        setUser(data.user);
        setIsAuthenticated(true);
        
        // リフレッシュトークンは自動でCookieに保存される
        router.push('/dashboard'); // ダッシュボードへ遷移
      } else {
        throw new Error('ログインに失敗しました');
      }
    } catch (error) {
      alert(error.message);
    }
  };
```


### 3. API呼び出しの実装（自動リフレッシュ付き）

```javascript
// utils/apiClient.js
export const apiClient = {
  async request(url, options = {}) {
    // 1回目のリクエスト
    let response = await fetch(url, {
      ...options,
      headers: {
        'Authorization': `Bearer ${getAccessToken()}`,
        'Content-Type': 'application/json',
        ...options.headers
      }
    });

    // 401エラー（期限切れ）の場合、自動でリフレッシュを試行
    if (response.status === 401) {
      const refreshed = await this.refreshToken();
      
      if (refreshed) {
        // リフレッシュ成功：元のリクエストを再実行
        response = await fetch(url, {
          ...options,
          headers: {
            'Authorization': `Bearer ${getAccessToken()}`,
            'Content-Type': 'application/json',
            ...options.headers
          }
        });
      } else {
        // リフレッシュ失敗：ログアウト処理
        logout();
        router.push('/login');
        return null;
      }
    }

    return response;
  },

  async refreshToken() {
    try {
      const response = await fetch('/api/auth/refresh', {
        credentials: 'include' // Cookie を自動送信
      });

      if (response.ok) {
        const data = await response.json();
        setAccessToken(data.accessToken); // 新しいトークンを保存
        return true;
      }
    } catch (error) {
      console.error('リフレッシュに失敗:', error);
    }
    return false;
  }
};
```


### 4. 保護されたページの実装

```javascript
// pages/dashboard.js
export default function Dashboard() {
  const { isAuthenticated, loading, user } = useAuth();
  const [userData, setUserData] = useState(null);

  // 認証チェック
  if (loading) return <div>読み込み中...</div>;
  if (!isAuthenticated) {
    router.push('/login');
    return null;
  }

  // ユーザーデータの取得
  useEffect(() => {
    const fetchUserData = async () => {
      // 自動リフレッシュ機能付きのAPI呼び出し
      const response = await apiClient.request('/api/user/profile');
      
      if (response?.ok) {
        const data = await response.json();
        setUserData(data);
      }
    };

    fetchUserData();
  }, []);

  return (
    <div>
      <h1>ダッシュボード</h1>
      <p>こんにちは、{user?.name}さん！</p>
      {userData && (
        <div>
          <h2>プロフィール情報</h2>
          <p>メール: {userData.email}</p>
          <p>登録日: {userData.createdAt}</p>
        </div>
      )}
    </div>
  );
}
```


### 5. ログインフォームの実装

```javascript
// pages/login.js
export default function LoginPage() {
  const { login, isAuthenticated } = useAuth();
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [isSubmitting, setIsSubmitting] = useState(false);

  // すでにログイン済みの場合はダッシュボードへ
  if (isAuthenticated) {
    router.push('/dashboard');
    return null;
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    
    try {
      await login(formData.email, formData.password);
    } catch (error) {
      console.error('ログインエラー:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label>メールアドレス</label>
        <input
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({...formData, email: e.target.value})}
          required
        />
      </div>
      
      <div>
        <label>パスワード</label>
        <input
          type="password"
          value={formData.password}
          onChange={(e) => setFormData({...formData, password: e.target.value})}
          required
        />
      </div>
      
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'ログイン中...' : 'ログイン'}
      </button>
    </form>
  );
}
```


### 6. サーバーサイド（API Routes）

```javascript
// pages/api/auth/login.js
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  const { email, password } = req.body;

  try {
    // データベースでユーザー認証
    const user = await authenticateUser(email, password);
    
    if (!user) {
      return res.status(401).json({ message: '認証に失敗しました' });
    }

    // JWTトークンを生成
    const accessToken = generateAccessToken(user); // 5-15分の有効期限
    const refreshToken = generateRefreshToken(user); // 数日〜数週間

    // リフレッシュトークンをHttpOnly Cookieに設定
    res.setHeader('Set-Cookie', [
      `refreshToken=${refreshToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}` // 7日間
    ]);

    // アクセストークンをレスポンスで返す（フロントはメモリに保存）
    res.status(200).json({
      accessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'サーバーエラー' });
  }
}

// pages/api/auth/refresh.js
export default async function handler(req, res) {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({ message: 'リフレッシュトークンがありません' });
  }

  try {
    // リフレッシュトークンの検証
    const decoded = verifyRefreshToken(refreshToken);
    const user = await getUserById(decoded.userId);

    if (!user) {
      return res.status(401).json({ message: 'ユーザーが見つかりません' });
    }

    // 新しいアクセストークンを生成
    const newAccessToken = generateAccessToken(user);

    res.status(200).json({
      accessToken: newAccessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(401).json({ message: 'トークンが無効です' });
  }
}
```


### 7. 実装のポイント

**✅ セキュリティ**
- アクセストークンは **メモリのみ** に保存
- リフレッシュトークンは **HttpOnly Cookie**
- API呼び出し時に **自動リフレッシュ** を実装

**✅ ユーザー体験**
- ページリロード時も **認証状態を維持**
- トークン期限切れを **ユーザーに意識させない**
- ローディング状態を **適切に表示**

**✅ エラーハンドリング**
- 401エラー時の **自動リトライ機能**
- ログイン失敗時の **分かりやすいメッセージ**


## 本番運用での監視・ログ・トラブルシューティング

### 1. メトリクス監視の実装

```typescript
// 認証メトリクスの収集
class AuthMetrics {
  private static instance: AuthMetrics;
  
  // ログイン成功率の監視
  trackLoginAttempt(success: boolean, method: 'password' | 'oauth' | 'sso') {
    const labels = { success: success.toString(), method };
    prometheus.loginAttempts.inc(labels);
    
    if (!success) {
      // 異常検知: 5分間で失敗率が30%を超えたらアラート
      this.checkFailureRate();
    }
  }
  
  // トークンリフレッシュの監視
  trackTokenRefresh(success: boolean, reason: 'expired' | 'revoked' | 'invalid') {
    prometheus.tokenRefreshes.inc({ success: success.toString(), reason });
  }
  
  // セッション継続時間の監視
  trackSessionDuration(userId: string, duration: number) {
    prometheus.sessionDuration.observe(duration);
    
    // 異常に長いセッション検知
    if (duration > 24 * 60 * 60 * 1000) { // 24時間
      this.alertLongSession(userId, duration);
    }
  }
}
```

### 2. セキュリティログの構造化

```typescript
// 構造化ログの実装
interface SecurityEvent {
  event_type: 'login' | 'logout' | 'token_refresh' | 'suspicious_activity';
  user_id?: string;
  ip_address: string;
  user_agent: string;
  timestamp: string;
  success: boolean;
  metadata: Record<string, any>;
}

const securityLogger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'security.log' }),
    // ELK Stack や Datadog に送信
    new winston.transports.Http({
      host: 'logs.yourapp.com',
      port: 443,
      path: '/security-events'
    })
  ]
});

// 使用例
securityLogger.info('User login attempt', {
  event_type: 'login',
  user_id: 'user_123',
  ip_address: req.ip,
  user_agent: req.headers['user-agent'],
  success: true,
  metadata: {
    login_method: 'password',
    mfa_enabled: true,
    device_fingerprint: deviceId
  }
});
```

### 3. パフォーマンス最適化

```typescript
// JWT 検証のキャッシュ化
class JWTValidator {
  private cache = new LRU<string, { valid: boolean; payload: any }>({
    maxSize: 10000,
    ttl: 5 * 60 * 1000 // 5分間キャッシュ
  });
  
  async validateToken(token: string): Promise<{ valid: boolean; payload?: any }> {
    // キャッシュヒット判定
    const cached = this.cache.get(token);
    if (cached) {
      return cached;
    }
    
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: ['HS256'],
        issuer: 'auth.yourapp.com',
        audience: 'api.yourapp.com'
      });
      
      const result = { valid: true, payload };
      this.cache.set(token, result);
      return result;
    } catch (error) {
      const result = { valid: false };
      // 短時間だけ失敗もキャッシュ（不正トークンの繰り返し検証を防ぐ）
      this.cache.set(token, result, { ttl: 30 * 1000 });
      return result;
    }
  }
}
```


## 実装チェックリスト（本番デプロイ前）

### 🔒 セキュリティ（必須項目）
- [ ] JWT アルゴリズムを明示的に指定 (`algorithms: ['HS256']`)
  - *確認方法*: `jwt.verify(token, secret, { algorithms: ['HS256'] })` の形で固定
- [ ] トークンの `iss`, `aud`, `exp` クレームを検証
  - *確認方法*: 発行者・対象者・有効期限をすべてサーバー側で検証
- [ ] リフレッシュトークンローテーションを実装
  - *確認方法*: 古いリフレッシュトークンが即座に無効化されることを確認
- [ ] Rate Limiting (ログイン試行: 5回/15分)
  - *実装例*: express-rate-limit や nginx の limit_req_zone
- [ ] CSRF トークンまたは SameSite=Strict Cookie
  - *確認方法*: クロスサイトからのフォーム送信がブロックされることを確認

### 🚀 パフォーマンス（推奨項目）
- [ ] JWT 検証結果のキャッシュ (Redis/Memory)
  - *期待効果*: 署名検証処理を 80% 削減
- [ ] トークンリフレッシュの同時実行制御
  - *確認方法*: 同じユーザーの同時リフレッシュが1回だけ実行されること
- [ ] バックエンドでの JWT 署名検証の並列化
  - *実装*: Worker Threads や Cluster モジュール活用
- [ ] CDN での静的リソース配信
  - *効果*: フロントエンドの読み込み速度向上

### 📊 監視・ログ（運用必須）
- [ ] 認証成功/失敗のメトリクス収集
  - *ツール*: Prometheus + Grafana or Datadog
- [ ] 異常なログイン試行の検知・アラート
  - *閾値例*: 1時間に10回以上の失敗でSlack通知
- [ ] セッション継続時間の監視
  - *目的*: 異常に長いセッション（攻撃の可能性）を検知
- [ ] ELK Stack での構造化ログ分析
  - *ログ項目*: IP、User-Agent、成功/失敗、レスポンス時間

### 🧪 テスト（品質保証）
- [ ] JWT アルゴリズム混乱攻撃のテスト
  - *テスト内容*: `{"alg": "none"}` でトークンが拒否されることを確認
- [ ] Concurrent リフレッシュのテスト
  - *テスト内容*: 同時実行時にRace Conditionが発生しないことを確認
- [ ] トークン漏洩時の無効化テスト
  - *テスト内容*: ユーザーの全セッション強制終了が正常に動作することを確認
- [ ] ブラウザ別 Cookie 動作テスト
  - *対象ブラウザ*: Chrome, Firefox, Safari, Edge の最新版とIE11

### 📋 運用準備チェック
- [ ] 環境変数の設定確認 (JWT_SECRET, REFRESH_SECRET等)
- [ ] データベースのインデックス設定 (user_id, session_id等)
- [ ] ログローテーションの設定 (logrotate等)
- [ ] 障害時のロールバック手順書の作成


# まとめ：JWT認証の実装で押さえるべきポイント

## 技術選択の判断基準

### JWT を選ぶべき場面
- **スケーラビリティ重視**: 10,000 RPS 以上の高負荷
- **マイクロサービス**: サービス間での認証情報共有が必要
- **グローバル展開**: CDNエッジでの認証判定
- **モバイルアプリ**: ネイティブアプリでのトークン管理

### セッション認証を選ぶべき場面
- **セキュリティ重視**: 金融・医療など高セキュリティ要件
- **小規模システム**: ユーザー数 < 1,000人
- **管理機能重視**: 強制ログアウト・セッション管理が頻繁

## 実装時の重要ポイント

### 1. セキュリティ設計
- **アルゴリズム固定**: `algorithms: ['HS256']` で攻撃を防ぐ
- **トークンローテーション**: リフレッシュトークンの使い捨て
- **適切な有効期限**: アクセス15分、リフレッシュ7日

### 2. パフォーマンス最適化
- **キャッシュ戦略**: JWT検証結果のメモリキャッシュ
- **同時実行制御**: Race Condition の回避
- **プロアクティブリフレッシュ**: 期限切れ前の事前更新

### 3. 運用面の考慮
- **構造化ログ**: セキュリティインシデントの追跡
- **メトリクス監視**: Prometheus + Grafana での可視化  
- **アラート設定**: 異常パターンの早期検知

## よくある質問と回答

**Q: なぜアクセストークンをlocalStorageに保存してはいけない？**
A: XSS攻撃でJavaScriptから読み取られるため。メモリ保存 + HttpOnly Cookieでリフレッシュが安全。

**Q: JWT vs セッション、どちらが安全？**
A: 実装次第。JWTは「スケーラブルだが無効化が困難」、セッションは「管理しやすいがボトルネック」。

**Q: トークンの有効期限はどう決める？**
A: アクセス15分（UX重視）、リフレッシュ7日（セキュリティ重視）が一般的。業務要件に応じて調整。

**Q: 本番で障害が起きたらどうする？**
A: 1) メトリクス確認、2) ログ分析、3) トークンローテーション強制実行、4) 必要に応じて全セッション無効化。

## 3・4年目エンジニアへのメッセージ

実務での JWT 認証実装では、**単純な仕組みの理解だけでなく、セキュリティ・パフォーマンス・運用性の3つの観点から設計する**ことが重要です。
