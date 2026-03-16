// Vulnerable: error details sent to client
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.get('/api/data', async (req, res) => {
  try {
    const data = await fetchData();
    res.json(data);
  } catch (error) {
    res.send(error.stack);
  }
});
