// Safe: generic error to client, details to server log
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

app.get('/api/data', async (req, res) => {
  try {
    const data = await fetchData();
    res.json(data);
  } catch (error) {
    logger.error({ err: error, requestId: req.id }, 'Failed to fetch data');
    res.status(500).json({ error: 'Something went wrong', requestId: req.id });
  }
});
