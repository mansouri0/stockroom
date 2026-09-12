const product = document.querySelector('#productId');
const quantity = document.querySelector('#quantity');
if (product && quantity) {
  const updateSaleTotal = () => {
    const selected = product.options[product.selectedIndex];
    const price = Number(selected?.dataset.price || 0);
    const stock = Number(selected?.dataset.stock || 0);
    const amount = Math.max(0, Number(quantity.value) || 0);
    quantity.max = stock || '';
    document.querySelector('#saleTotal').textContent = `$${(price * amount).toFixed(2)}`;
    document.querySelector('#stockHint').textContent = stock ? `${stock} units available` : 'Select a product to see available stock.';
  };
  product.addEventListener('change', updateSaleTotal);
  quantity.addEventListener('input', updateSaleTotal);
}
