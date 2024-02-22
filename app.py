from flask import Flask, request, session, redirect, url_for, render_template, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from datetime import datetime
import pytz 
#from mfrc522 import SimpleMFRC522
#from RPi import GPIO

#reader = SimpleMFRC522()


app = Flask(__name__)
app.secret_key = 'jinkazama16'
app.jinja_env.globals.update(cart_items=[])

# Configure the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'admin_cpe4a2022-2023'

db = SQLAlchemy(app)

app.config['TIMEZONE'] = 'UTC'
def datetimeformat(value, format='%Y-%m-%dT%H:%M'):
    return value.strftime(format)

app.jinja_env.filters['datetimeformat'] = datetimeformat

# Initialize Flask-Migrate
migrate = Migrate(app, db)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(120), unique=True, nullable=False)
    type = db.Column(db.String(100), nullable=False)
    availability = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    return_date = db.Column(db.DateTime, nullable=True)  # New column for return date
    borrower_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def serialize(self):
        return {
            'id': self.id,
            'code': self.code,
            'type': self.type,
            'availability': self.availability,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M') if self.timestamp else None,
            'return_date': self.return_date.strftime('%Y-%m-%d %H:%M') if self.return_date else None,
            'borrower_id': self.borrower_id,
            'borrower_username': self.borrower.username if self.borrower else None
        }
        
# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    student_code = db.Column(db.String(20), unique=True, nullable=False)
    is_superuser = db.Column(db.Boolean, default=False)
    is_restricted = db.Column(db.Boolean, default=False)
    borrowed_items = db.relationship('Item', backref='borrower', lazy=True)

    # Create the database tables for the default and 'items' databases
def create_superuser():
    with app.app_context():
        superuser = User(username='admin_superuser', password=generate_password_hash('admin_password1234'), student_code='6E5535A5AB', is_superuser=True)
        db.session.add(superuser)
        db.session.commit()

migrate = Migrate(app, db)
cart_list = []
#---------------------------------------------------------------------------------------------------#
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    login_failed = False
    session.pop('user_id', None)
    

    if request.method == 'POST':
        username_or_code = request.form['usernameOrCode']
        password = request.form['password']
        hidden_student_code = request.form['hidden_rfidResult']

        # Check if the input matches either username/password or student code
        user = User.query.filter(or_(
            (User.username == username_or_code),
            (User.student_code == username_or_code),
            (User.student_code == hidden_student_code)
        )).first()

        if user:
            # Check if the login is by username/password
            if user.username == username_or_code and check_password_hash(user.password, password):
                session['user_id'] = user.id

                if user.is_superuser:
                    return redirect(url_for('superuser_settings'))
                else:
                    return redirect(url_for('login_successful'))
            # Check if the login is by student code only
            elif user.student_code == username_or_code or user.student_code == hidden_student_code:
                session['user_id'] = user.id
                if user.is_superuser:
                    return redirect(url_for('superuser_settings'))
                else:
                    return redirect(url_for('login_successful'))
                
        # If no matching user is found or passwords don't match, set login_failed to True
        login_failed = True

    return render_template('login.html', login_failed=login_failed)

@app.route('/register', methods=['GET', 'POST'])
def register():
    register_failed = False
    register_success = False
    id_missing = False
    student_code=""
    
    global cart_list
    cart_list = []  

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        student_code = request.form['student_code']

        # Check if the username or student_code already exists in the database
        existing_user = User.query.filter((User.username == username) | (User.student_code == student_code)).first()

        if existing_user:
            register_failed = True
            flash('Username or student code already exists. Please choose different ones.', 'error')
        else:
            try:
                if student_code == "ID MISSING" or student_code == "" or student_code == "( SCANNING )":
                    id_missing = True
                    register_failed = False
                else:
                    # Hash the password before storing it
                    password_hash = generate_password_hash(password)
                    new_user = User(username=username, password=password_hash, student_code=student_code, is_restricted=False)
                    db.session.add(new_user)
                    db.session.commit()
                    flash('Registration successful. You can now log in.', 'success')
                    register_success = True
                    register_failed = False
                    id_missing = False
                    return redirect(url_for('registered'))

            except IntegrityError as e:
                db.session.rollback()  # Rollback the transaction
                register_failed = True
                flash('Error: Student code already exists.', 'error')
                print(f"IntegrityError: {e}")

    return render_template('register.html', register_failed=register_failed, register_success=register_success, student_code=student_code, id_missing=id_missing)

@app.route('/options', methods=['GET', 'POST'])
def options():
    if 'user_id' not in session:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))
    return render_template('options.html')
@app.route('/read_rfid', methods=['POST'])
def read_rfid():
    try:
        rfid_id = reader.read_id()

        if rfid_id:
            hex_rfid_id = format(rfid_id, 'X')
            user = User.query.filter(User.student_code == rfid_id).first()
            item = Item.query.filter(Item.code == rfid_id).first()

            if user:
                session['user_id'] = user.id
                session['username'] = user.username
                session['password'] = user.password                
                hex_rfid_id = format(rfid_id, 'X')
                session['user_id'] = user.id
                return jsonify({'rfid_id': rfid_id, 'username': user.username, 'password': user.password})
            else:
                hex_rfid_id = format(rfid_id, 'X')
                return jsonify({'rfid_id': hex_rfid_id})        

        return jsonify({'error': 'No card detected'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/check_user_exist', methods=['POST'])
def check_user_exist():
    rfid_value = request.json.get('rfidValue')

    user = User.query.filter_by(student_code=rfid_value).first()

    return jsonify({'userExist': user is not None})

@app.route('/check_item_exist', methods=['POST'])
def check_item_exist():
    rfid_value = request.json.get('rfidValue')

    item = Item.query.filter_by(code=rfid_value).first()

    return jsonify({'itemExist': item is not None})            
#---------------------------------------------------------------------------------------------------#
@app.route('/restricted', methods=['GET'])
def restricted():
    return render_template('restricted.html')

@app.route('/restricted_return', methods=['GET'])
def restricted_return():
    return render_template('restricted-return.html')

@app.route('/return_successful', methods=['GET'])
def return_successful():
    return render_template('return_successful.html')

@app.route('/registered', methods=['GET'])
def registered():
    return render_template('registered.html')

@app.route('/login_successful', methods=['GET'])
def login_successful():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        
        return render_template('login_successful.html',user=user)
@app.route('/borrowsuccess', methods=['GET'])
def borrowsuccess():
    
    return render_template('borrowsuccess.html')

@app.route('/borrow', methods=['GET', 'POST'])
def borrow():
    user = None
    id_code = None

    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        id_code = User.query.get(session['user_id'])
        
        if user.is_restricted:
        # Check if the user is restricted, and redirect if necessary
            flash('You are restricted and cannot access the borrow page. Redirecting to options page...', 'error')
            return redirect(url_for('restricted'))
    else:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))

    # Check for overdue items and restrict users if necessary
    check_user_restriction()

    # Filter items based on the condition:
    kb = Item.query.filter(Item.type.contains("kb"), Item.availability == 1).order_by(Item.code).all()
    ms = Item.query.filter(Item.type.contains("ms"), Item.availability == 1).order_by(Item.code).all()
    mnt = Item.query.filter(Item.type.contains("mnt"), Item.availability == 1).order_by(Item.code).all()
    psu = Item.query.filter(Item.type.contains("psu"), Item.availability == 1).order_by(Item.code).all()
    etc = Item.query.filter(Item.type.contains("etc"), Item.availability == 1).order_by(Item.code).all()

    borrowed_items = Item.query.filter_by(availability=False).all()

    # Get the current datetime in Asia/Manila time zone
    current_datetime_manila = datetime.now(pytz.timezone('Asia/Manila'))

    # Extract date and time components separately
    date_part = current_datetime_manila.strftime('%Y-%m-%d')
    time_part = current_datetime_manila.strftime('%H:%M')

    return render_template('borrow_page.html', user=user, id_code=id_code, kb=kb, ms=ms, mnt=mnt, psu=psu, etc=etc, item=Item, borrowed_items=borrowed_items, current_date=date_part, current_time=time_part, current_datetime=current_datetime_manila)

@app.route('/checkItemExist', methods=['POST'])
def checkItemExist():
    rfid_value = request.json.get('rfidValue')
    item = Item.query.filter_by(code=rfid_value).first()

    if item:
        if item.availability:
            # Item is present and available
            print(f"Item Available - Code: {item.code}, Type: {item.type}")
            return jsonify({'itemAvailable': True, 'code': item.code, 'rfidType': item.type})
        else:
            print(f"Item Borrowed - Code: {item.code}, Type: {item.type}")
            return jsonify({'itemBorrowed': True, 'code': item.code, 'rfidType': item.type})
    else:
        print(f"Item Not Available - Code: {rfid_value}")
        # Item is not present or not available
        return jsonify({'itemAvailable': False, 'itemBorrowed': False, 'code': None, 'rfidType': None})

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    try:
        rfid_result = request.json.get('rfidResult')
        user_id = session.get('user_id')
        
        if user_id is not None:
            item = Item.query.filter_by(code=rfid_result).first()
            
            if item:
                # Retrieve or initialize the user's cart in the session
                user_cart = session.get(f'user_{user_id}_cart', [])
                print(f'Item found: {item}')
                
                # Check if the item is already in the cart
                if not any(cart_item['code'] == rfid_result for cart_item in user_cart):
                    user_cart.append(item.serialize())
                    session[f'user_{user_id}_cart'] = user_cart

                    print(f'Cart contents: {user_cart}')
                    return jsonify(success=True, message='Item added to cart')
                else:
                    return jsonify(success=False, message='Item is already in the cart')
            else:
                return jsonify(success=False, message='Item not found')
        else:
            return jsonify(success=False, message='User not logged in')
    except Exception as e:
        return jsonify(success=False, message=str(e))

@app.route('/get_cart_items', methods=['GET'])
def get_cart_items():
    user_id = session.get('user_id')
    
    if user_id is not None:
        # Retrieve the user's cart from the session
        user_cart = session.get(f'user_{user_id}_cart', [])

        return jsonify(success=True, cart_items=user_cart)
    else:
        return jsonify(success=False, error='User not logged in')
    
@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    try:
        code_to_remove = request.json.get('code')
        user_id = session.get('user_id')
        
        # Check if the item is in the cart list before attempting removal
        if user_id is not None:
            user_cart = session.get(f'user_{user_id}_cart', [])
            
            item_to_remove = next((item for item in user_cart if item['code'] == code_to_remove), None)

            if item_to_remove:
                user_cart.remove(item_to_remove)

                # Update the cart in the session after removal
                session[f'user_{user_id}_cart'] = user_cart
                return jsonify(success=True, message='Item removed from cart', cart_items=user_cart)
            else:
                return jsonify(success=False, message='Item not found in cart')
        else:
            return jsonify(success=False, message='User not logged in')
    except Exception as e:
        return jsonify(success=False, message=str(e))
#------------------------------------------------------------------------------BORROW SECTION--------------------------------------------------------------------------------------------#
def check_user_restriction():
    overdue_items = Item.query.filter(Item.availability == False, Item.return_date < datetime.now()).all()

    for item in overdue_items:
        borrower = User.query.get(item.borrower_id)
        if borrower:
            borrower.is_restricted = True
            db.session.commit()
@app.route('/confirm_borrow', methods=['POST'])
def confirm_borrow():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user and (user.is_superuser or not user.is_restricted):
            # Extract the cart items from the session
            cart_items = session.get(f'user_{user_id}_cart', [])

            # Extract return date and time from the form data
            return_date_str = request.form.get('return-datetime')

            # Use the correct format for parsing the date and time
            if return_date_str:
                return_date = datetime.strptime(return_date_str, '%Y-%m-%dT%H:%M')

                borrow_success = False
                is_restricted = False  # Assume the user won't be restricted

                # Update the availability, borrower information, and return date for each item
                for item in cart_items:
                    item_code = item.get('code')
                    db_item = Item.query.filter_by(code=item_code).first()

                    if db_item:
                        # Check if the return date is in the past and the item is still marked as borrowed
                        if db_item.return_date and db_item.return_date < datetime.now() and not db_item.availability:
                            is_restricted = True  # Set user as restricted

                        db_item.availability = False
                        db_item.borrower_id = user.id
                        db_item.timestamp = datetime.now()  # Set the timestamp to the current time
                        db_item.return_date = return_date  # Set return date from the form data

                        # Commit changes for the current item
                        db.session.commit()

                        borrow_success = True

                # Check if the user should be restricted and update the database
                if is_restricted:
                    user.is_restricted = True
                    db.session.commit()

                # Clear the user's cart after confirmation
                session.pop(f'user_{user_id}_cart', None)

                # Use flash to store a temporary message
                if borrow_success:
                    flash('Items confirmed and marked as borrowed.', 'success')
                    return redirect(url_for('borrowsuccess'))
                else:
                    flash('Error confirming borrow. User not authenticated or unauthorized.', 'error')

                # Redirect to the borrow page
                return redirect(url_for('borrow'))

    # Provide an error response if the conditions are not met
    flash('Error confirming borrow. User not authenticated or unauthorized.', 'error')
    return redirect(url_for('borrow'))

#------------------------------------------------------------------------------RETURN SECTION--------------------------------------------------------------------------------------------#

@app.route('/return_items', methods=['GET', 'POST'])
def return_items():
    user = None
    id_code = None
    select_condition=False
    
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        id_code = User.query.get(session['user_id'])
        
        if request.method == 'POST':
            # Use get method to safely retrieve form data with a default value
            itemCode = request.form.get('hidden_itemCode', '')
            itemType = request.form.get('hidden_itemType', '')
            itemCondition = request.form.get('hidden_itemcondition', '')

            # Print the values to the console
            print(f'itemCode: {itemCode}, itemType: {itemType}, itemCondition: {itemCondition}')

            # Check if the item exists in the database
            item = Item.query.filter_by(code=itemCode, type=itemType).first()

            if item and itemCondition == 'GOOD' and item.availability == 0:
                # Update the item details in the database
                item.availability = 1
                item.timestamp = datetime.now()
                item.borrower_id = None
                item.return_date = None
                db.session.commit()
                return redirect(url_for('return_successful'))
                
            elif item and itemCondition == 'DAMAGED' and item.availability == 0:
                user.is_restricted = 1
                item.availability = 1
                item.timestamp = datetime.now()
                item.borrower_id = None
                item.return_date = None
                db.session.commit()
                return redirect(url_for('restricted_return'))

            else:
                select_condition=True

    return render_template('return.html', user=user, id_code=id_code, select_condition=select_condition)

#------------------------------------------------------------------------------SUPERUSER SECTION--------------------------------------------------------------------------------------------#
@app.route('/superuser_settings', methods=['GET', 'POST'])
def superuser_settings():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.is_superuser:
            if request.method == 'POST':
                # Handle adding a new user
                if request.form['action'] == 'add_user':
                    new_username = request.form['new_username']
                    new_password = request.form['new_password']
                    new_student_code = request.form['new_student_code']
                    
                    
                    if not User.query.filter((User.username == new_username) | (User.student_code == new_student_code)).first():
                        new_user = User(username=new_username, password=generate_password_hash(new_password), student_code=new_student_code)
                        db.session.add(new_user)
                        db.session.commit()
                        flash('User added successfully.', 'success')

                # Handle deleting a user
                elif request.form['action'] == 'delete_user':
                    user_id = int(request.form['user_id'])
                    user_to_delete = User.query.get(user_id)
                    
                    if user_to_delete:
                        db.session.delete(user_to_delete)
                        db.session.commit()
                        flash('User deleted successfully.', 'success')
                    
                elif request.form['action'] == 'delete_item':
                    item_id = int(request.form['item_id'])
                    item_to_delete = User.query.get(item_id)
                    
                    if item_to_delete:
                        db.session.delete(item_to_delete)
                        db.session.commit()
                        flash('User deleted successfully.', 'success')
                        
                elif request.form['action'] == 'unrestrict_user':
                    user_id = int(request.form['user_id'])
                    user_to_unrestrict = User.query.get(user_id)
                    
                    if user_to_unrestrict:
                        user_to_unrestrict.is_restricted = False
                        db.session.commit()
                        flash('User unresticted successfully.', 'success')
                    

            registered_users = User.query.filter_by(is_superuser=False, is_restricted=False).all()
            restricted_users = User.query.filter_by(is_restricted=True).all()
            registered_items = Item.query.filter_by(availability=True).all()
            borrowed_items = Item.query.filter_by(availability=False).all()

            return render_template('superuser_settings.html', user=user, registered_users=registered_users,
                                   registered_items=registered_items, restricted_users=restricted_users, borrowed_items=borrowed_items, 
                                   item=Item)

    return redirect(url_for('login'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.is_superuser:
            user_to_delete = User.query.get(user_id)
            if user_to_delete:
                db.session.delete(user_to_delete)
                db.session.commit()
                flash('User deleted successfully.', 'success')
    return redirect(url_for('superuser_settings'))

@app.route('/unrestrict_user/<int:user_id>', methods=['POST'])
def unrestrict_user(user_id):
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.is_superuser:
            user_to_unrestrict = User.query.get(user_id)
            if user_to_unrestrict:
                user_to_unrestrict.is_restricted = False
                db.session.commit()
                flash('User unrestricted successfully.', 'success')
    return redirect(url_for('superuser_settings'))

@app.route('/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        
        if user.is_superuser:
            item_to_delete = Item.query.get(item_id)
            if item_to_delete:
                db.session.delete(item_to_delete)
                db.session.commit()
                flash('Item deleted successfully.', 'success')
    return redirect(url_for('superuser_settings'))


# Add User Route
@app.route('/add_user', methods=['POST'])
def add_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.is_superuser:
            if request.method == 'POST':
                new_username = request.form['new_username']
                new_student_code = request.form['new_student_code']
                new_password = request.form['new_password']
                is_admin = 'new_admin' in request.form
                
                if not User.query.filter_by(username=new_username).first():
                    new_user = User(username=new_username, 
                                    student_code=new_student_code, 
                                    password=generate_password_hash(new_password),
                                    is_superuser=is_admin)
                    
                    db.session.add(new_user)
                    db.session.commit()
                    flash('User added successfully.', 'success')
    return redirect(url_for('superuser_settings'))
@app.route('/add_item', methods=['POST'])
def add_item():
    
    item_error = session.pop('item_error', False)
    
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.is_superuser:
            if request.method == 'POST':
                item_code = request.form['item_code']
                item_type = request.form['item_type']

                existing_item = Item.query.filter(Item.code == item_code).first()
                print(f'item_code')
                
                if existing_item:
                    item_error = True
                    
                if item_code == 'undefined':
                    item_error = True

                else:
                    # Create and add the new item to the 'items' database
                    new_item = Item(code=item_code, type=item_type, availability = True)
                    db.session.add(new_item)  # Use 'db_items' to access the 'items' database
                    db.session.commit()
                    flash('Item added successfully.', 'success')
            
    return redirect(url_for('superuser_settings',item_error=item_error))
#---------------------------------------------------------------------------------------------------#
@app.route('/borrow_settings', methods=['GET', 'POST'])
def borrow_settings():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        session['username'] = user.username
        session['student_code'] = user.student_code
        change_error = False
        change_success = False
        
        if request.method == 'POST':
                change_username = request.form['username']
                change_password = request.form['password']
                
                print(f"user.password: {user.password}")
                print(f"change_password: {change_password}")
                
                if check_password_hash(user.password, change_password):
                    if change_username:  # Check if a new username is provided
                        existing_user = User.query.filter(User.username == change_username).first()
                        if existing_user:
                            change_error = True
                        else:
                            user.username = change_username
                            
                    db.session.commit()
                    change_success = True
                    return redirect(url_for('borrow_settings'))
                
                if user.username == change_username:
                    if change_password:  # Check if a new password is provided
                        user.password = generate_password_hash(change_password)
                    
                    db.session.commit()
                    change_success = True

        
                else:
                    change_error = True
                            
                # Store the change_error state in the session
                session['change_error'] = change_error
                session['change_success'] = change_success


    else:
        # If the user is not logged in, redirect to the login page or handle as appropriate
        return redirect('/login')  # Change the URL as needed

    # Reset the change_error and change_success states to False before rendering the template
    session['change_error'] = False
    session['change_success'] = False
                
    return render_template('borrowoptions.html', user=user, username=user.username, change_error=change_error, change_success=change_success)

#---------------------------------------------------------------------------------------------------#

@app.route('/return_settings', methods=['GET', 'POST'])
def return_settings():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        session['username'] = user.username
        session['student_code'] = user.student_code
        change_error = False
        change_success = False
        
        if request.method == 'POST':
                change_username = request.form['username']
                change_password = request.form['password']
                
                print(f"user.password: {user.password}")
                print(f"change_password: {change_password}")
                
                if check_password_hash(user.password, change_password):
                    if change_username:  # Check if a new username is provided
                        existing_user = User.query.filter(User.username == change_username).first()
                        if existing_user:
                            change_error = True
                        else:
                            user.username = change_username
                            
                    db.session.commit()
                    change_success = True
                    return redirect(url_for('borrow_settings'))
                
                if user.username == change_username:
                    if change_password:  # Check if a new password is provided
                        user.password = generate_password_hash(change_password)
                    
                    db.session.commit()
                    change_success = True

        
                else:
                    change_error = True
                            
                # Store the change_error state in the session
                session['change_error'] = change_error
                session['change_success'] = change_success


    else:
        # If the user is not logged in, redirect to the login page or handle as appropriate
        return redirect('/login')  # Change the URL as needed

    # Reset the change_error and change_success states to False before rendering the template
    session['change_error'] = False
    session['change_success'] = False
                
    return render_template('returnoptions.html', user=user, username=user.username, change_error=change_error, change_success=change_success)
#---------------------------------------------------------------------------------------------------#
@app.route('/borrow_back')
def borrow_back():
    return redirect(url_for('borrow'))

@app.route('/return_back')
def return_back():
    return redirect(url_for('return_items'))
#---------------------------------------------------------------------------------------------------#
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))
#---------------------------------------------------------------------------------------------------#
if __name__ == '__main__':
    current_time = datetime.now()
    print(f'Current Time: {current_time}')
    app.run(debug=True, port=5001)