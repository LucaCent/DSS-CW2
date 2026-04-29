/**
 * ============================================================
 * SECURE BLOG — Client-Side Application Logic
 * ============================================================
 * This file handles navigation, form submissions, and API calls.
 * All state-changing requests include the CSRF token.
 * Client-side validation provides immediate feedback but is
 * always backed by server-side validation.
 * ============================================================
 */

// ── State ────────────────────────────────────────────────────
let csrfToken = null;
let currentUser = null;
let pendingDeleteId = null;

// ── Initialisation ───────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await fetchCSRFToken();
  await checkAuth();
  navigate('home');

  // Character counter for post content
  const postContent = document.getElementById('post-content');
  if (postContent) {
    postContent.addEventListener('input', () => {
      document.getElementById('content-count').textContent = postContent.value.length;
    });
  }

  const editContent = document.getElementById('edit-content');
  if (editContent) {
    editContent.addEventListener('input', () => {
      document.getElementById('edit-content-count').textContent = editContent.value.length;
    });
  }
});

// ── CSRF Token ───────────────────────────────────────────────
async function fetchCSRFToken() {
  try {
    const res = await fetch('/auth/csrf-token');
    const data = await res.json();
    csrfToken = data.csrfToken;
  } catch (err) {
    console.error('Failed to fetch CSRF token');
  }
}

// ── Auth Check ───────────────────────────────────────────────
async function checkAuth() {
  try {
    const res = await fetch('/auth/me');
    if (res.ok) {
      currentUser = await res.json();
      updateNavAuth(true);
    } else {
      currentUser = null;
      updateNavAuth(false);
    }
  } catch (err) {
    currentUser = null;
    updateNavAuth(false);
  }
}

function updateNavAuth(loggedIn) {
  document.getElementById('auth-nav').style.display = loggedIn ? 'none' : 'inline';
  document.getElementById('user-nav').style.display = loggedIn ? 'inline' : 'none';
  if (loggedIn && currentUser) {
    document.getElementById('nav-username').textContent = currentUser.username;
  }
}

// ── Navigation ───────────────────────────────────────────────
function navigate(page) {
  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.style.display = 'none');

  // Reset alerts
  document.querySelectorAll('.alert').forEach(a => { a.style.display = 'none'; a.textContent = ''; });

  const target = document.getElementById('page-' + page);
  if (target) {
    target.style.display = 'block';
  }

  // Page-specific logic
  switch (page) {
    case 'home':
      loadPosts();
      break;
    case 'my-posts':
      if (!currentUser) { navigate('login'); return; }
      loadMyPosts();
      break;
    case 'create-post':
      if (!currentUser) { navigate('login'); return; }
      document.getElementById('create-post-form').reset();
      document.getElementById('content-count').textContent = '0';
      break;
    case 'search':
      document.getElementById('search-results').innerHTML = '';
      document.getElementById('no-search-results').style.display = 'none';
      break;
  }
}

// ── API Helper ───────────────────────────────────────────────
async function apiCall(url, method = 'GET', body = null) {
  const options = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };

  if (body) {
    if (csrfToken) body._csrf = csrfToken;
    options.body = JSON.stringify(body);
  }

  if (method !== 'GET' && csrfToken) {
    options.headers['x-csrf-token'] = csrfToken;
  }

  const res = await fetch(url, options);
  const data = await res.json();

  if (!res.ok) {
    throw new Error(data.error || 'An error occurred');
  }

  return data;
}

// ── Registration ─────────────────────────────────────────────
async function handleRegister(event) {
  event.preventDefault();
  const errorEl = document.getElementById('register-error');
  errorEl.style.display = 'none';

  const username = document.getElementById('reg-username').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;

  // Client-side validation
  if (username.length < 3 || username.length > 50) {
    showError(errorEl, 'Username must be 3–50 characters');
    return;
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    showError(errorEl, 'Username may only contain letters, numbers, and underscores');
    return;
  }
  if (password.length < 8) {
    showError(errorEl, 'Password must be at least 8 characters');
    return;
  }

  try {
    const data = await apiCall('/auth/register', 'POST', { username, email, password });

    // Show 2FA setup page
    document.getElementById('qr-code-container').innerHTML = `<img src="${data.qrCode}" alt="2FA QR Code">`;
    document.getElementById('totp-manual-key').textContent = data.totpSecret;
    document.getElementById('2fa-user-id').value = data.userId;

    navigate('2fa-setup');
  } catch (err) {
    showError(errorEl, err.message);
  }
}

// ── Enable 2FA ───────────────────────────────────────────────
async function handleEnable2FA(event) {
  event.preventDefault();
  const errorEl = document.getElementById('2fa-error');
  errorEl.style.display = 'none';

  const userId = document.getElementById('2fa-user-id').value;
  const totpCode = document.getElementById('verify-totp').value.trim();

  if (!/^\d{6}$/.test(totpCode)) {
    showError(errorEl, 'Please enter a 6-digit code');
    return;
  }

  try {
    await apiCall('/auth/enable-2fa', 'POST', { userId: parseInt(userId), totpCode });
    alert('2FA enabled successfully! You can now log in.');
    navigate('login');
  } catch (err) {
    showError(errorEl, err.message);
  }
}

// ── Login ────────────────────────────────────────────────────
async function handleLogin(event) {
  event.preventDefault();
  const errorEl = document.getElementById('login-error');
  const infoEl = document.getElementById('login-info');
  errorEl.style.display = 'none';
  infoEl.style.display = 'none';

  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const totpCode = document.getElementById('login-totp').value.trim();

  if (!username || !password) {
    showError(errorEl, 'Username and password are required');
    return;
  }

  try {
    const body = { username, password };
    if (totpCode) body.totpCode = totpCode;

    const data = await apiCall('/auth/login', 'POST', body);

    if (data.requires2FA) {
      // Show 2FA input
      document.getElementById('totp-group').style.display = 'block';
      showInfo(infoEl, 'Please enter the 6-digit code from your authenticator app');
      document.getElementById('login-totp').focus();
      return;
    }

    // Login successful
    csrfToken = data.csrfToken;
    currentUser = data.user;
    updateNavAuth(true);
    await checkAuth();
    navigate('home');
  } catch (err) {
    showError(errorEl, err.message);
  }
}

// ── Logout ───────────────────────────────────────────────────
async function handleLogout() {
  try {
    await apiCall('/auth/logout', 'POST', {});
  } catch (err) {
    // Continue with client-side logout even if server call fails
  }
  currentUser = null;
  csrfToken = null;
  updateNavAuth(false);
  await fetchCSRFToken();
  navigate('home');
}

// ── Load Posts (Public) ──────────────────────────────────────
async function loadPosts() {
  try {
    const data = await apiCall('/posts');
    renderPosts(data.posts, 'posts-list', 'no-posts', false);
  } catch (err) {
    console.error('Failed to load posts:', err.message);
  }
}

// ── Load My Posts ────────────────────────────────────────────
async function loadMyPosts() {
  try {
    const data = await apiCall('/posts');
    const myPosts = data.posts.filter(p => p.author === currentUser.username);
    renderPosts(myPosts, 'my-posts-list', 'no-my-posts', true);
  } catch (err) {
    console.error('Failed to load posts:', err.message);
  }
}

// ── Render Posts ─────────────────────────────────────────────
function renderPosts(posts, containerId, emptyId, showActions) {
  const container = document.getElementById(containerId);
  const emptyEl = document.getElementById(emptyId);

  if (!posts || posts.length === 0) {
    container.innerHTML = '';
    if (emptyEl) emptyEl.style.display = 'block';
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';

  container.innerHTML = posts.map(post => `
    <div class="post-card">
      <h2>${post.title}</h2>
      <div class="post-meta">
        By <strong>${post.author}</strong> &middot;
        ${new Date(post.createdAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}
        ${post.updatedAt && post.updatedAt !== post.createdAt ? ' (edited)' : ''}
      </div>
      <div class="post-body">${post.content}</div>
      ${showActions ? `
        <div class="post-actions">
          <button class="btn btn-sm btn-primary" onclick="startEditPost(${post.id})">Edit</button>
          <button class="btn btn-sm btn-danger" onclick="confirmDeletePost(${post.id})">Delete</button>
        </div>
      ` : ''}
    </div>
  `).join('');
}

// ── Create Post ──────────────────────────────────────────────
async function handleCreatePost(event) {
  event.preventDefault();
  const errorEl = document.getElementById('create-error');
  errorEl.style.display = 'none';

  const title = document.getElementById('post-title').value.trim();
  const content = document.getElementById('post-content').value.trim();

  if (!title || title.length > 200) {
    showError(errorEl, 'Title is required (max 200 characters)');
    return;
  }
  if (!content || content.length > 5000) {
    showError(errorEl, 'Content is required (max 5000 characters)');
    return;
  }

  try {
    await apiCall('/posts', 'POST', { title, content });
    navigate('my-posts');
  } catch (err) {
    showError(errorEl, err.message);
  }
}

// ── Edit Post ────────────────────────────────────────────────
async function startEditPost(postId) {
  try {
    const data = await apiCall(`/posts/${postId}`);
    document.getElementById('edit-post-id').value = data.id;
    // Decode HTML entities for editing
    document.getElementById('edit-title').value = decodeHTMLEntities(data.title);
    document.getElementById('edit-content').value = decodeHTMLEntities(data.content);
    document.getElementById('edit-content-count').textContent = decodeHTMLEntities(data.content).length;
    navigate('edit-post');
  } catch (err) {
    alert('Failed to load post: ' + err.message);
  }
}

async function handleEditPost(event) {
  event.preventDefault();
  const errorEl = document.getElementById('edit-error');
  errorEl.style.display = 'none';

  const postId = document.getElementById('edit-post-id').value;
  const title = document.getElementById('edit-title').value.trim();
  const content = document.getElementById('edit-content').value.trim();

  if (!title || title.length > 200) {
    showError(errorEl, 'Title is required (max 200 characters)');
    return;
  }
  if (!content || content.length > 5000) {
    showError(errorEl, 'Content is required (max 5000 characters)');
    return;
  }

  try {
    await apiCall(`/posts/${postId}`, 'PUT', { title, content });
    navigate('my-posts');
  } catch (err) {
    showError(errorEl, err.message);
  }
}

// ── Delete Post ──────────────────────────────────────────────
function confirmDeletePost(postId) {
  pendingDeleteId = postId;
  document.getElementById('delete-modal').style.display = 'flex';
  document.getElementById('confirm-delete-btn').onclick = () => executeDelete();
}

function closeDeleteModal() {
  document.getElementById('delete-modal').style.display = 'none';
  pendingDeleteId = null;
}

async function executeDelete() {
  if (!pendingDeleteId) return;
  try {
    await apiCall(`/posts/${pendingDeleteId}`, 'DELETE', {});
    closeDeleteModal();
    loadMyPosts();
  } catch (err) {
    closeDeleteModal();
    alert('Failed to delete post: ' + err.message);
  }
}

// ── Search ───────────────────────────────────────────────────
async function handleSearch(event) {
  event.preventDefault();
  const query = document.getElementById('search-input').value.trim();
  const resultsEl = document.getElementById('search-results');
  const noResultsEl = document.getElementById('no-search-results');

  if (!query) return;
  if (query.length > 200) {
    alert('Search query must be 200 characters or less');
    return;
  }

  try {
    const data = await apiCall(`/posts/search?q=${encodeURIComponent(query)}`);
    if (data.posts.length === 0) {
      resultsEl.innerHTML = '';
      noResultsEl.textContent = `No posts found matching "${query}"`;
      noResultsEl.style.display = 'block';
    } else {
      noResultsEl.style.display = 'none';
      renderPosts(data.posts, 'search-results', null, false);
    }
  } catch (err) {
    resultsEl.innerHTML = '';
    noResultsEl.textContent = 'An error occurred while searching.';
    noResultsEl.style.display = 'block';
  }
}

// ── Password Reset Request ───────────────────────────────────
async function handleResetRequest(event) {
  event.preventDefault();
  const errorEl = document.getElementById('reset-req-error');
  const successEl = document.getElementById('reset-req-success');
  errorEl.style.display = 'none';
  successEl.style.display = 'none';

  const username = document.getElementById('reset-username').value.trim();
  if (!username) {
    showError(errorEl, 'Username is required');
    return;
  }

  try {
    const data = await apiCall('/password-reset/request', 'POST', { username });
    showSuccess(successEl, data.message);

    if (data.resetToken) {
      document.getElementById('reset-token-value').textContent = data.resetToken;
      document.getElementById('reset-token-display').style.display = 'block';
    }
  } catch (err) {
    showError(errorEl, err.message);
  }
}

// ── Password Reset Confirm ───────────────────────────────────
async function handleResetConfirm(event) {
  event.preventDefault();
  const errorEl = document.getElementById('reset-conf-error');
  const successEl = document.getElementById('reset-conf-success');
  errorEl.style.display = 'none';
  successEl.style.display = 'none';

  const token = document.getElementById('reset-token-input').value.trim();
  const newPassword = document.getElementById('reset-new-password').value;

  if (!token || !newPassword) {
    showError(errorEl, 'Token and new password are required');
    return;
  }

  if (newPassword.length < 8) {
    showError(errorEl, 'Password must be at least 8 characters');
    return;
  }

  try {
    const data = await apiCall('/password-reset/confirm', 'POST', { token, newPassword });
    showSuccess(successEl, data.message);
  } catch (err) {
    showError(errorEl, err.message);
  }
}

// ── Helpers ──────────────────────────────────────────────────
function showError(el, message) {
  el.textContent = message;
  el.style.display = 'block';
}

function showSuccess(el, message) {
  el.textContent = message;
  el.style.display = 'block';
}

function showInfo(el, message) {
  el.textContent = message;
  el.style.display = 'block';
}

function decodeHTMLEntities(text) {
  const textarea = document.createElement('textarea');
  textarea.innerHTML = text;
  return textarea.value;
}
