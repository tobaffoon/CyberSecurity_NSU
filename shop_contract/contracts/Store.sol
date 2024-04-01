// SPDX-License-Identifier: MIT

pragma solidity ^0.8.11;

error InsufficientQuantity(uint available, uint required);

contract Store {
    address public owner;

    enum Product{
        Greenfield,
        Lipton,
        Java
    }

    enum OrderStatus{
        Delivering,
        Delivered,
        Canceled
    }

    struct order{
        uint price;
        address customer;
        mapping(Product => uint) contents;
        OrderStatus status;
    }
    uint latestOrderId = 0;

    string[3] public availableProducts;
    mapping(Product => uint) public priceList; // product -> price per item
    mapping(Product => uint) public warehouse; // product -> quantity available
    mapping(uint => order) orders; // orders_id -> product -> quantity (what was ordered) + status
    mapping(address => mapping(Product => uint)) public carts; // customer -> product -> quantity taken

// requires 1 850 453 $ to deploy
    constructor(){
        availableProducts[0] = "Greenfield";
        availableProducts[1] = "Lipton";
        availableProducts[2] = "Java";

        priceList[Product.Greenfield] = 100;
        priceList[Product.Lipton] = 70;
        priceList[Product.Java] = 90;

        warehouse[Product.Greenfield] = 100;
        warehouse[Product.Lipton] = 50;
        warehouse[Product.Java] = 500;
    }

    modifier correctOrderId(uint id){
        require(id <= latestOrderId, "Order with this ID is not created yet");
        _;
    }
    
    function calculateCartPrice(mapping(Product => uint) storage _cart) internal view returns(uint){
        uint sum = 0;
        sum += priceList[Product.Greenfield] * _cart[Product.Greenfield];
        sum += priceList[Product.Lipton] * _cart[Product.Lipton];
        sum += priceList[Product.Java] * _cart[Product.Java];
        return sum;
    }

    function putProductIntoCart(Product _product, uint _quantity) external {
        carts[msg.sender][_product] += _quantity;

        // require(carts[msg.sender][_product] <= warehouse[_product], "Not enough products in warehouse");
        if(carts[msg.sender][_product] > warehouse[_product]){
            revert InsufficientQuantity({
                available: warehouse[_product],
                required: carts[msg.sender][_product]
            });
        }
    }

    function clearCart(mapping(Product => uint) storage _cart) internal {
        _cart[Product.Greenfield] = 0;
        _cart[Product.Lipton] = 0;
        _cart[Product.Java] = 0;
    }

    function reserveProducts(order storage _order) internal {
        warehouse[Product.Greenfield] -= _order.contents[Product.Greenfield];
        warehouse[Product.Lipton] -= _order.contents[Product.Greenfield];
        warehouse[Product.Java] -= _order.contents[Product.Greenfield];
    }

    function returnProducts(order storage _order) internal {
        warehouse[Product.Greenfield] += _order.contents[Product.Greenfield];
        warehouse[Product.Lipton] += _order.contents[Product.Greenfield];
        warehouse[Product.Java] += _order.contents[Product.Greenfield];
    }

// return id of new order
    function purchase() external payable returns(uint) {
        address customer = msg.sender;
        mapping(Product => uint) storage cart = carts[customer];
        uint cartPrice = calculateCartPrice(cart);

        latestOrderId++;
        order storage newOrder = orders[latestOrderId];
        newOrder.price = cartPrice;
        newOrder.customer = customer;
        newOrder.contents[Product.Greenfield] = cart[Product.Greenfield];
        newOrder.contents[Product.Lipton] = cart[Product.Lipton];
        newOrder.contents[Product.Java] = cart[Product.Java];
        newOrder.status = OrderStatus.Delivering;

        clearCart(cart);
        reserveProducts(newOrder);

        require(msg.value >= cartPrice, "Not enough money sent");
        payable(msg.sender).transfer(msg.value - cartPrice);

        return latestOrderId;
    }

    function cancelOrder(uint id) external correctOrderId(id) {
        order storage cancellingOrder = orders[id];
        require(cancellingOrder.status == OrderStatus.Delivering, "Order is either already cancelled or delivered");

        returnProducts(cancellingOrder);
        payable(cancellingOrder.customer).transfer(cancellingOrder.price); // return money
        cancellingOrder.status = OrderStatus.Canceled;
    }

    function confirmDelivered(uint id) external correctOrderId(id) {
        order storage deliveredOrder = orders[id];
        require(deliveredOrder.status == OrderStatus.Delivering, "Order is either already cancelled or delivered");

        deliveredOrder.status = OrderStatus.Delivered;
        payable(owner).transfer(deliveredOrder.price);
    }
}