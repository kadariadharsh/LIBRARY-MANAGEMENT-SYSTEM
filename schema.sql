-- Run this in DB browser or via Python script

CREATE TABLE library_books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    author TEXT,
    department TEXT,
    purchase_date TEXT,
    price REAL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    phone TEXT,
    email TEXT
);

CREATE TABLE issued_books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    book_id INTEGER,
    borrower_name TEXT,
    phone TEXT,
    issue_date TEXT,
    return_date TEXT,
    FOREIGN KEY(book_id) REFERENCES library_books(id)
);
