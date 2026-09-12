const productModal = new bootstrap.Modal('#productModal');
const productForm = document.querySelector('#productForm');
document.querySelector('#newProduct').addEventListener('click', () => {
  productForm.reset(); productForm.action = '/products';
  document.querySelector('#productModalTitle').textContent = 'Add product';
});
document.querySelectorAll('.edit-product').forEach(button => button.addEventListener('click', () => {
  const product = JSON.parse(decodeURIComponent(button.dataset.product));
  productForm.action = `/products/${product.id}`;
  ['name', 'sku', 'qty', 'price'].forEach(key => { productForm.elements[key].value = product[key]; });
  document.querySelector('#productModalTitle').textContent = 'Edit product';
  productModal.show();
}));
