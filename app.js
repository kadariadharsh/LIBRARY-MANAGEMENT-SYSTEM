const express = require('express');
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware to parse JSON bodies
app.use(express.json());

// In-memory storage for books
let books = [
  { id: 1, title: 'The Great Gatsby', author: 'F. Scott Fitzgerald', available: true },
  { id: 2, title: 'To Kill a Mockingbird', author: 'Harper Lee', available: true },
  { id: 3, title: '1984', author: 'George Orwell', available: true }
];

// Route to get all books
app.get('/books', (req, res) => {
  res.json(books);
});

// Route to add a new book
app.post('/books', (req, res) => {
  const newBook = req.body;
  newBook.id = books.length + 1; // Simple ID generation
  newBook.available = true;
  books.push(newBook);
  res.status(201).json(newBook);
});

// Route to get a specific book by ID
app.get('/books/:id', (req, res) => {
  const book = books.find(b => b.id === parseInt(req.params.id));
  if (!book) return res.status(404).send('Book not found');
  res.json(book);
});

// Route to update a book
app.put('/books/:id', (req, res) => {
  const book = books.find(b => b.id === parseInt(req.params.id));
  if (!book) return res.status(404).send('Book not found');
  Object.assign(book, req.body);
  res.json(book);
});

// Route to delete a book
app.delete('/books/:id', (req, res) => {
  const bookIndex = books.findIndex(b => b.id === parseInt(req.params.id));
  if (bookIndex === -1) return res.status(404).send('Book not found');
  books.splice(bookIndex, 1);
  res.status(204).send();
});

app.get('/', (req, res) => {
  res.send('Hello, World!');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on http://0.0.0.0:${PORT}`);
}); 