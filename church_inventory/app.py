from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from io import StringIO, BytesIO
from datetime import datetime
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import zipfile
import logging

app = Flask(__name__)
app.secret_key = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.logger.setLevel(logging.DEBUG)
handler = logging.FileHandler('app.log')
app.logger.addHandler(handler)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------- MODELS ---------- #
class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    category = db.Column(db.String(50))
    condition = db.Column(db.String(50))
    locations = db.relationship('ItemLocation', backref='item', lazy=True)

class ItemLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    location = db.relationship('Location', backref='items')

class Movement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory.id'), nullable=False)
    quantity = db.Column(db.Integer)
    from_location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    to_location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    movement_date = db.Column(db.String(20))
    responsible_person = db.Column(db.String(100))

class DisposedItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(100), nullable=False)
    disposal_date = db.Column(db.Date, nullable=False)
    disposed_by = db.Column(db.String(100), nullable=False)
    notes = db.Column(db.String(200))
    item = db.relationship('Inventory', backref='disposals')
    location = db.relationship('Location', backref='disposals')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# ---------- INITIAL SETUP ---------- #
def create_default_admin():
    with app.app_context():
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()

with app.app_context():
    db.create_all()
    create_default_admin()

# ---------- AUTHENTICATION ROUTES ---------- #
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('User created successfully', 'success')
        return redirect(url_for('index'))
    return render_template('register.html')

# ---------- INVENTORY ROUTES ---------- #
@app.route('/')
@login_required
def index():
    # Only show items with at least one location having quantity > 0
    inventory = Inventory.query.join(ItemLocation).filter(ItemLocation.quantity > 0).all()
    return render_template('index.html', inventory=inventory)

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        try:
            name = request.form['name']
            description = request.form['description']
            category = request.form['category']
            condition = request.form['condition']
            location_name = request.form['location']
            quantity = int(request.form['quantity'])

            item = Inventory(
                name=name,
                description=description,
                category=category,
                condition=condition
            )
            db.session.add(item)
            db.session.commit()

            location = Location.query.filter_by(name=location_name).first()
            if not location:
                location = Location(name=location_name)
                db.session.add(location)
                db.session.commit()

            item_loc = ItemLocation(
                item_id=item.id,
                location_id=location.id,
                quantity=quantity
            )
            db.session.add(item_loc)
            db.session.commit()
            flash('Item added successfully', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error adding item: {str(e)}', 'danger')
            return redirect(url_for('add_item'))

    categories = db.session.query(Inventory.category.distinct()).all()
    conditions = db.session.query(Inventory.condition.distinct()).all()
    locations = Location.query.all()
    return render_template('add_item.html',
                         categories=[c[0] for c in categories],
                         conditions=[c[0] for c in conditions],
                         locations=locations)

@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Inventory.query.get_or_404(item_id)
    if request.method == 'POST':
        try:
            item.name = request.form['name']
            item.description = request.form['description']
            item.category = request.form['category']
            item.condition = request.form['condition']
            db.session.commit()
            flash('Item updated successfully', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating item: {str(e)}', 'danger')
    return render_template('edit_item.html', item=item)

@app.route('/dispose_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def dispose_item(item_id):
    # Get the item we're trying to dispose
    item = Inventory.query.get_or_404(item_id)
    
    if request.method == 'POST':
        try:
            # 1. Get form data
            location_id = int(request.form['location'])
            quantity = int(request.form['quantity'])
            reason = request.form['reason']
            notes = request.form.get('notes', '')  # Optional field
            disposal_date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()

            # 2. Find the item's location information
            item_location = ItemLocation.query.filter_by(
                item_id=item.id,
                location_id=location_id
            ).first()

            # 3. Validate we have enough stock
            if not item_location:
                flash("This item doesn't exist in the selected location", 'danger')
                return redirect(url_for('dispose_item', item_id=item.id))
                
            if item_location.quantity < quantity:
                flash(f"Only {item_location.quantity} available in this location", 'danger')
                return redirect(url_for('dispose_item', item_id=item.id))

            # 4. Update inventory
            item_location.quantity -= quantity
            
            # Remove location entry if quantity reaches zero
            if item_location.quantity == 0:
                db.session.delete(item_location)

            # 5. Record disposal
            disposal_record = DisposedItem(
                item_id=item.id,
                location_id=location_id,
                quantity=quantity,
                reason=reason,
                disposal_date=disposal_date,
                disposed_by=current_user.username,
                notes=notes
            )
            db.session.add(disposal_record)

            # 6. Save all changes
            db.session.commit()
            flash('Disposal recorded successfully!', 'success')
            return redirect(url_for('index'))

        except ValueError as e:
            db.session.rollback()
            flash(f'Invalid input: {str(e)}', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Error processing disposal: {str(e)}', 'danger')
            app.logger.error(f'Disposal error: {str(e)}')

    # GET REQUEST HANDLING
    # Get all locations where this item has stock
    available_locations = db.session.query(Location).join(ItemLocation).filter(
        ItemLocation.item_id == item.id,
        ItemLocation.quantity > 0
    ).all()

    # If no locations available, show warning
    if not available_locations:
        flash('This item has no stock in any location', 'warning')
        return redirect(url_for('index'))

    return render_template('dispose_form.html',
                         item=item,
                         locations=available_locations,
                         date_today=datetime.now().date())

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    if request.method == 'POST':
        try:
            # Validate and parse form data
            item_id = int(request.form['item_id'])
            from_location_id = int(request.form['from_location'])
            to_location_id = int(request.form['to_location'])
            quantity = int(request.form['quantity'])
            movement_date = request.form['date']
            responsible = request.form['responsible'].strip()

            # Basic validations
            if from_location_id == to_location_id:
                raise ValueError("Source and destination locations cannot be the same")
            
            if quantity <= 0:
                raise ValueError("Quantity must be greater than zero")

            # Verify item still exists with stock
            item = Inventory.query.filter(
                Inventory.id == item_id,
                Inventory.locations.any(ItemLocation.quantity > 0)
            ).first()
            
            if not item:
                raise ValueError("Item no longer exists in inventory")

            # Find source location with stock
            source = ItemLocation.query.filter(
                ItemLocation.item_id == item_id,
                ItemLocation.location_id == from_location_id,
                ItemLocation.quantity > 0
            ).first()

            if not source:
                raise ValueError("Item not found in source location")
            if source.quantity < quantity:
                raise ValueError(f"Only {source.quantity} available in source location")

            # Start atomic transaction
            with db.session.begin_nested():
                # Update source
                source.quantity -= quantity
                if source.quantity <= 0:
                    db.session.delete(source)

                # Update destination
                destination = ItemLocation.query.filter_by(
                    item_id=item_id,
                    location_id=to_location_id
                ).first()
                
                if destination:
                    destination.quantity += quantity
                else:
                    db.session.add(ItemLocation(
                        item_id=item_id,
                        location_id=to_location_id,
                        quantity=quantity
                    ))

                # Record movement
                movement = Movement(
                    item_id=item_id,
                    quantity=quantity,
                    from_location_id=from_location_id,
                    to_location_id=to_location_id,
                    movement_date=movement_date,
                    responsible_person=responsible
                )
                db.session.add(movement)

            db.session.commit()
            flash('Transfer completed successfully', 'success')
            return redirect(url_for('transfer'))

        except ValueError as e:
            db.session.rollback()
            flash(f'Transfer failed: {str(e)}', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Transfer error: {str(e)}', exc_info=True)
            flash('An unexpected error occurred during transfer', 'danger')

    # GET Request Handling
    try:
        # Get available items with stock
        items = Inventory.query.filter(
            Inventory.locations.any(ItemLocation.quantity > 0)
        ).options(
            db.joinedload(Inventory.locations)
        ).all()

        selected_item = None
        available_locations = []
        date_today = datetime.now().strftime('%Y-%m-%d')
        item_id = request.args.get('item_id', type=int)

        if item_id:
            # Verify item still has stock
            selected_item = next(
                (item for item in items if item.id == item_id), 
                None
            )
            
            if selected_item:
                # Get locations with available stock
                available_locations = [
                    loc.location for loc in selected_item.locations 
                    if loc.quantity > 0
                ]

        return render_template('transfer.html',
            items=items,
            all_locations=Location.query.all(),
            selected_item=selected_item,
            available_locations=available_locations,
            date_today=date_today
        )

    except Exception as e:
        app.logger.error(f'Transfer page error: {str(e)}', exc_info=True)
        flash('Error loading transfer page', 'danger')
        return redirect(url_for('index'))

# ---------- CSV HANDLING ---------- #
@app.route('/import_csv', methods=['POST'])
@login_required
def import_csv():
    if 'csv_file' not in request.files:
        return redirect(url_for('index'))
    
    file = request.files['csv_file']
    if file.filename == '':
        return redirect(url_for('index'))
    
    if file and file.filename.endswith('.csv'):
        try:
            stream = file.read().decode('utf-8').splitlines()
            csv_file = csv.DictReader(stream)
            
            for row in csv_file:
                item = Inventory.query.filter_by(
                    name=row['Name'],
                    description=row['Description'],
                    category=row['Category'],
                    condition=row['Condition']
                ).first()
                
                if not item:
                    item = Inventory(
                        name=row['Name'],
                        description=row['Description'],
                        category=row['Category'],
                        condition=row['Condition']
                    )
                    db.session.add(item)
                    db.session.commit()
                
                location = Location.query.filter_by(name=row['Location']).first()
                if not location:
                    location = Location(name=row['Location'])
                    db.session.add(location)
                    db.session.commit()
                
                item_loc = ItemLocation.query.filter_by(
                    item_id=item.id,
                    location_id=location.id
                ).first()
                
                if item_loc:
                    item_loc.quantity += int(row['Quantity'])
                else:
                    item_loc = ItemLocation(
                        item_id=item.id,
                        location_id=location.id,
                        quantity=int(row['Quantity'])
                    )
                    db.session.add(item_loc)
            
            db.session.commit()
            flash('CSV imported successfully', 'success')
            
        except Exception as e:
            flash(f'Error importing CSV: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/export_csv')
@login_required
def export_csv():
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zip_file:
        # Inventory CSV
        inventory_data = StringIO()
        writer = csv.writer(inventory_data)
        writer.writerow(['ID', 'Name', 'Description', 'Category', 'Condition', 'Location', 'Quantity'])
        for item_loc in ItemLocation.query.all():
            writer.writerow([
                item_loc.item.id,
                item_loc.item.name,
                item_loc.item.description,
                item_loc.item.category,
                item_loc.item.condition,
                item_loc.location.name,
                item_loc.quantity
            ])
        zip_file.writestr('inventory.csv', inventory_data.getvalue().encode('utf-8'))
        
        # Movements CSV
        movements_data = StringIO()
        writer = csv.writer(movements_data)
        writer.writerow(['ID', 'Item ID', 'Item Name', 'Quantity', 'From Location', 'To Location', 'Date', 'Responsible'])
        for move in Movement.query.all():
            from_loc = Location.query.get(move.from_location_id).name if move.from_location_id else 'N/A'
            to_loc = Location.query.get(move.to_location_id).name if move.to_location_id else 'N/A'
            item_name = Inventory.query.get(move.item_id).name
            writer.writerow([
                move.id,
                move.item_id,
                item_name,
                move.quantity,
                from_loc,
                to_loc,
                move.movement_date,
                move.responsible_person
            ])
        zip_file.writestr('movements.csv', movements_data.getvalue().encode('utf-8'))
        
        # Disposed Items CSV
        disposed_data = StringIO()
        writer = csv.writer(disposed_data)
        writer.writerow(['ID', 'Item ID', 'Item Name', 'Location', 'Quantity', 'Reason', 'Date', 'Disposed By', 'Notes'])
        for disposal in DisposedItem.query.all():
            writer.writerow([
                disposal.id,
                disposal.item_id,
                disposal.item.name,
                disposal.location.name,
                disposal.quantity,
                disposal.reason,
                disposal.disposal_date,
                disposal.disposed_by,
                disposal.notes
            ])
        zip_file.writestr('disposed_items.csv', disposed_data.getvalue().encode('utf-8'))
    
    buffer.seek(0)
    return send_file(
        buffer,
        download_name='inventory_export.zip',
        as_attachment=True,
        mimetype='application/zip'
    )

@app.route('/download_template')
@login_required
def download_template():
    text_buffer = StringIO()
    writer = csv.writer(text_buffer)
    writer.writerow(['Name', 'Description', 'Category', 'Condition', 'Location', 'Quantity'])
    writer.writerow(['Bible', 'NIV Hardcover', 'Books', 'New', 'Chapel Storage', 25])
    text_buffer.seek(0)
    return send_file(
        BytesIO(text_buffer.getvalue().encode('utf-8')),
        download_name='inventory_template.csv',
        as_attachment=True,
        mimetype='text/csv'
    )

@app.route('/disposed')
@login_required
def disposed_inventory():
    search_query = request.args.get('q', '')
    
    # Base query
    query = DisposedItem.query.join(Inventory).join(Location)
    
    # Apply search filter
    if search_query:
        query = query.filter(
            db.or_(
                Inventory.name.ilike(f'%{search_query}%'),
                Location.name.ilike(f'%{search_query}%'),
                DisposedItem.reason.ilike(f'%{search_query}%')
            )
        )
    
    disposed_items = query.order_by(DisposedItem.disposal_date.desc()).all()
    
    return render_template('disposed.html', 
                         disposed_items=disposed_items,
                         search_query=search_query)

# ---------- SEARCH FUNCTIONALITY ---------- #
@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    
    # Determine which page we're coming from
    referrer = request.referrer or ''
    
    if 'disposed' in referrer:
        # Search disposed items
        results = DisposedItem.query.join(Inventory).join(Location).filter(
            db.or_(
                Inventory.name.ilike(f'%{query}%'),
                Location.name.ilike(f'%{query}%'),
                DisposedItem.reason.ilike(f'%{query}%')
            )
        ).all()
        return render_template('disposed.html', disposed_items=results, search_query=query)
    else:
        # Original inventory search
        results = Inventory.query.filter(
            db.or_(
                Inventory.name.ilike(f'%{query}%'),
                Inventory.description.ilike(f'%{query}%'),
                Inventory.category.ilike(f'%{query}%')
            )
        ).all()
        return render_template('index.html', inventory=results, search_query=query)

if __name__ == '__main__':
    app.run(debug=True)