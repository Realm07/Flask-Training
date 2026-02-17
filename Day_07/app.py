from flask import Flask, jsonify, request

app =  Flask(__name__)

products = {
    "products": [{"item_id": 101, "name": "laptop", "price": 200000},
                 {"item_id": 102, "name": "mobile", "price": 10000}]
}

@app.route("/products")
def show_products():
    return jsonify(products)

@app.route("/products/add", methods=["POST"])
def add_product():
    pid = 100 + (len(products["products"])+1)
    pname = request.form.get("pname")
    price = request.form.get("price")

    if pname and price:
        new_product = {"item_id": pid, "name": str(pname), "price": int(price)}
        products["products"].append(new_product)

        return jsonify({
            "status": 200,
            "product": new_product,
            "message": "product added successfully"
        })
    
    return jsonify({
        "status": 400,
        "message": "No product name and price given"
    })

@app.route("/products/<int:pid>")
def product_by_id(id):
    pid = id 

    products_list = products["products"]
    for product in products_list:
        if product.get("item_id") == id:
            return jsonify({
                "code": 200,
                "product":product,
                "message": "success"
            })

    return jsonify({
        "code": 400,
        "message": "Product no found"
    })

if __name__ == "__main__":
    app.run(debug=True)