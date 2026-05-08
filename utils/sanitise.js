//encodes input to make script inert
function encodeHTML(input){
  if (typeof input != 'string') return '';

  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// Length limits enforced server-side — client-side validation can always be
// bypassed with curl. Also avoids DB column overflow on the TEXT columns.
const INPUT_LIMITS = {
  username: { min: 3, max: 50 },
  password: { min: 8, max: 128 },
  email: { min: 5, max: 254 },
  postTitle: { min: 1, max: 200 },
  postContent: { min: 1, max: 5000 },
  searchQuery: { min: 1, max: 200 },
  totpCode: { exact: 6 },
};

// Check a value against the min/max/exact rules for its field
function validateLength(field, value) {
  const limits = INPUT_LIMITS[field];
  if (!limits) return { valid: true, message: '' };

  if (typeof value !== 'string') {
    return { valid: false, message: `${field} must be a string` };
  }

  if (limits.exact && value.length !== limits.exact) {
    return { valid: false, message: `${field} must be exactly ${limits.exact} characters` };
  }

  if (limits.min && value.length < limits.min) {
    return { valid: false, message: `${field} must be at least ${limits.min} characters` };
  }

  if (limits.max && value.length > limits.max) {
    return { valid: false, message: `${field} must be at most ${limits.max} characters` };
  }

  return { valid: true, message: '' };
}

// Username: letters, digits, underscores only
function validateUsername(username) {
  const lengthCheck = validateLength('username', username);
  if (!lengthCheck.valid) return lengthCheck;

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return { valid: false, message: 'Username may only contain letters, numbers, and underscores' };
  }
  return { valid: true, message: '' };
}

// Basic email format check
function validateEmail(email) {
  const lengthCheck = validateLength('email', email);
  if (!lengthCheck.valid) return lengthCheck;

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { valid: false, message: 'Invalid email format' };
  }
  return { valid: true, message: '' };
}

// Password strength rules
function validatePassword(password) {
  const lengthCheck = validateLength('password', password);
  if (!lengthCheck.valid) return lengthCheck;

  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number' };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one special character' };
  }
  return { valid: true, message: '' };
}

module.exports = {
  encodeHTML,
  validateLength,
  validateUsername,
  validateEmail,
  validatePassword,
  INPUT_LIMITS,
};
