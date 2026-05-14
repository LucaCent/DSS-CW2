/*
 * Blog post routes — public listing, search, and authenticated CRUD.
 * Every query is parameterised, all output is HTML-encoded, and
 * edit/delete check ownership so users can only touch their own posts.
 */

const express = require('express');
const router = express.Router();
const pool = require('../db/pool');
const { requireAuth } = require('../middleware/sessionCheck');
const { encodeHTML, validateLength } = require('../utils/sanitise');
const logger = require('../utils/logger');

// GET /posts — Public post listing (no auth required)


router.get('/', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, u.username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       ORDER BY p.created_at DESC`
    );

    // HTML-encode everything before it leaves the server
    const posts = result.rows.map((post) => ({
      id: post.id,
      title: encodeHTML(post.title),
      content: encodeHTML(post.content),
      createdAt: post.created_at,
      updatedAt: post.updated_at,
      author: encodeHTML(post.username),
    }));

    res.json({ posts });
  } catch (err) {
    console.error('Get posts error:', err.message);
    res.status(500).json({ error: 'An error occurred while fetching posts.' });
  }
});


// GET /posts/search?q=keyword — Search posts by keyword

router.get('/search', async (req, res) => {
  try {
    const { q } = req.query;

    if (!q) {
      return res.status(400).json({ error: 'Search query is required' });
    }

    const queryCheck = validateLength('searchQuery', q);
    if (!queryCheck.valid) return res.status(400).json({ error: queryCheck.message });

    // Wildcards go inside the parameter, not in the SQL string itself
    const searchTerm = `%${q}%`;
    const result = await pool.query(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, u.username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       WHERE p.title ILIKE $1 OR p.content ILIKE $1
       ORDER BY p.created_at DESC`,
      [searchTerm]
    );

    const posts = result.rows.map((post) => ({
      id: post.id,
      title: encodeHTML(post.title),
      content: encodeHTML(post.content),
      createdAt: post.created_at,
      updatedAt: post.updated_at,
      author: encodeHTML(post.username),
    }));

    res.json({ posts });
  } catch (err) {
    console.error('Search error:', err.message);
    res.status(500).json({ error: 'An error occurred while searching.' });
  }
});


// GET /posts/:id — Get a single post

router.get('/:id', async (req, res) => {
  try {
    const postId = parseInt(req.params.id, 10);
    if (isNaN(postId)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const result = await pool.query(
      `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, p.user_id, u.username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       WHERE p.id = $1`,
      [postId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const post = result.rows[0];
    res.json({
      id: post.id,
      title: encodeHTML(post.title),
      content: encodeHTML(post.content),
      createdAt: post.created_at,
      updatedAt: post.updated_at,
      userId: post.user_id,
      author: encodeHTML(post.username),
    });
  } catch (err) {
    console.error('Get post error:', err.message);
    res.status(500).json({ error: 'An error occurred while fetching the post.' });
  }
});


// POST /posts — Create a new post (auth required)

router.post('/', requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body;

    const titleCheck = validateLength('postTitle', title);
    if (!titleCheck.valid) return res.status(400).json({ error: titleCheck.message });

    const contentCheck = validateLength('postContent', content);
    if (!contentCheck.valid) return res.status(400).json({ error: contentCheck.message });

    const result = await pool.query(
      `INSERT INTO posts (user_id, title, content)
       VALUES ($1, $2, $3)
       RETURNING id, title, content, created_at`,
      [req.session.userId, title, content]
    );

    const post = result.rows[0];
    logger.info('Post created', { userId: req.session.userId, postId: post.id });

    res.status(201).json({
      message: 'Post created successfully',
      post: {
        id: post.id,
        title: encodeHTML(post.title),
        content: encodeHTML(post.content),
        createdAt: post.created_at,
      },
    });
  } catch (err) {
    console.error('Create post error:', err.message);
    res.status(500).json({ error: 'An error occurred while creating the post.' });
  }
});


// PUT /posts/:id — Edit a post (auth required, own posts only)

// Ownership check before edit — without this, any logged-in user could
// swap the post ID in the URL and overwrite someone else's post.
// Same check is in DELETE below.
router.put('/:id', requireAuth, async (req, res) => {
  try {
    const postId = parseInt(req.params.id, 10);
    if (isNaN(postId)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const { title, content } = req.body;

    const titleCheck = validateLength('postTitle', title);
    if (!titleCheck.valid) return res.status(400).json({ error: titleCheck.message });

    const contentCheck = validateLength('postContent', content);
    if (!contentCheck.valid) return res.status(400).json({ error: contentCheck.message });

    // Make sure this post belongs to the logged-in user
    const existing = await pool.query(
      'SELECT user_id FROM posts WHERE id = $1',
      [postId]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (existing.rows[0].user_id !== req.session.userId) {
      logger.security('IDOR attempt - edit post', {
        ip: req.ip,
        attackerUserId: req.session.userId,
        targetPostId: postId,
        ownerUserId: existing.rows[0].user_id,
      });
      return res.status(403).json({ error: 'You do not have permission to edit this post' });
    }

    const result = await pool.query(
      `UPDATE posts SET title = $1, content = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3
       RETURNING id, title, content, updated_at`,
      [title, content, postId]
    );

    const post = result.rows[0];
    logger.info('Post updated', { userId: req.session.userId, postId: post.id });

    res.json({
      message: 'Post updated successfully',
      post: {
        id: post.id,
        title: encodeHTML(post.title),
        content: encodeHTML(post.content),
        updatedAt: post.updated_at,
      },
    });
  } catch (err) {
    console.error('Update post error:', err.message);
    res.status(500).json({ error: 'An error occurred while updating the post.' });
  }
});


// DELETE /posts/:id — Delete a post (auth required, own posts only)

router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const postId = parseInt(req.params.id, 10);
    if (isNaN(postId)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }

    const existing = await pool.query(
      'SELECT user_id FROM posts WHERE id = $1',
      [postId]
    );

    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (existing.rows[0].user_id !== req.session.userId) {
      logger.security('IDOR attempt - delete post', {
        ip: req.ip,
        attackerUserId: req.session.userId,
        targetPostId: postId,
        ownerUserId: existing.rows[0].user_id,
      });
      return res.status(403).json({ error: 'You do not have permission to delete this post' });
    }

    await pool.query('DELETE FROM posts WHERE id = $1', [postId]);

    logger.info('Post deleted', { userId: req.session.userId, postId });

    res.json({ message: 'Post deleted successfully' });
  } catch (err) {
    console.error('Delete post error:', err.message);
    res.status(500).json({ error: 'An error occurred while deleting the post.' });
  }
});

module.exports = router;
