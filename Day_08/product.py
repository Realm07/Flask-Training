from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

app =  Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///memory.db"
db = SQLAlchemy(app)


class Product(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float(10,2), nullable=False)

@app.route("/products")
def show_products():
    products = Product.query.all()
    response = {}
    if products:
        products_list = []
        for product in products:
            id = product.pid
            pname = product.pname
            price = product.price

            products_list.append({
                    "pid":id,
                    "product_name":pname,
                    "price":price
                }
            )
        
        response["status"] = 200
        response["products"] = products_list
        response["message"] = "success"
        return jsonify(response)
    
    response["status"] = 400
    response["products"] = None
    response["message"] = "No products availiable"
    return jsonify(response)
    

@app.route("/products/add", methods=["POST"])
def add_product():
    pname = request.form.get("pname")
    price = request.form.get("price")

    if pname and price:
        new_product = Product()
        new_product.pname = str(pname).lower()
        new_product.price = round(float(price), 2)

        db.session.add(new_product)
        db.session.commit()

        return jsonify({
            "status": 200,
            "product": {"product_name":new_product.pname, "price":new_product.price},
            "message": "product added successfully"
        })
    
    return jsonify({
        "status": 400,
        "message": "No product name and price given"
    })

@app.route("/products/<int:pid>")
def product_by_id(id):
    product = Product.query.get(id)
    if product:
        return jsonify({
            "status": 200,
            "product": {"product_name":product.pname, "price":product.price},
            "message": "success"
        })

    return jsonify({
        "code": 400,
        "product":None,
        "message": "Product not found"
    })

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    
    app.run(debug=True)