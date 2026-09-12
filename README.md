
# Stockroom

A small Node.js and Express inventory tracker with a Bootstrap 5 interface.

## Run it

```bash
npm install
npm start
```

Then open http://localhost:3000.

If port 3000 is already in use, the app automatically starts on port 3001. To choose a port yourself, run `PORT=3100 npm start`.

The app keeps its data in `data/inventory.db`, a SQLite database driven by the Node 20-compatible `sqlite3` package.

## Included

- Add, edit, and delete products
- SQLite-backed `products` and `sales` tables
- REST CRUD endpoints at `/products` and a transactional `POST /sale` endpoint
- Search products by name or SKU
- Product, unit, and inventory-value summary cards
- Sales window with automatic stock deductions and recent-sale history
