// Safe: parameterized queries with explicit columns
const userId = req.params.id;
db.query("SELECT id, name, email FROM users WHERE id = $1", [userId]);
db.query("SELECT id, email FROM users WHERE email = ?", [req.body.email]);

// Safe: ORM with select
const user = await User.findByPk(userId, { attributes: ['id', 'name', 'email'] });
const post = await prisma.post.findUnique({ where: { id: postId }, select: { id: true, title: true } });
