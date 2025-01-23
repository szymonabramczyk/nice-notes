import time

import markdown

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user

from . import db, Config
from .forms import NoteForm, DecryptForm
from .models import Note
from .utils import encrypt, decrypt, decrypt_secret, sanitize_content, verify_signature, generate_signature

views = Blueprint('views', __name__)

@views.route('/')
@login_required
def home():
    if not current_user.is_two_factor_authentication_enabled:
        flash("You must enable 2-Factor Authentication to access this page.", "danger")
        return redirect(url_for('auth.setup_two_factor_auth'))
    return render_template("index.html")


@views.route('/add-note', methods=['GET', 'POST'])
@login_required
def add_note():
    form = NoteForm()
    if form.validate_on_submit():
        content = form.content.data
        nonce, tag = None, None

        # encrypt content if user chose to
        if form.is_encrypted.data:
            content, tag, nonce = encrypt(content.encode(), form.secret_key.data)

        # get encrypted private key
        encrypted_private_key = current_user.encrypted_private_key
        if not encrypted_private_key:
            flash("An error occurred.", "danger")
            return redirect(url_for('views.add_note'))

        # decrypt user's private key
        private_key = decrypt_secret(encrypted_private_key)

        # generate signature
        signature_base64 = generate_signature(content, private_key, form.is_encrypted.data)

        # make a list of emails provided by user
        shared_with = None
        if form.is_public.data and form.shared_with.data:
            shared_with = [email.strip() for email in form.shared_with.data.split(',')]

        note = Note(
            title=form.title.data,
            content=content,
            nonce=nonce,
            tag=tag,
            is_encrypted=form.is_encrypted.data,
            is_public=form.is_public.data,
            shared_with=shared_with,
            user_id=current_user.id,
            signature=signature_base64
        )

        try:
            db.session.add(note)
            db.session.commit()
            flash('Note added successfully!', 'success')
            return redirect(url_for('views.home'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while saving the note. Please try again.', 'danger')

    return render_template('add-note.html', form=form)


@views.route('/edit-note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()

    # verify signature
    if not verify_signature(note.content, note.signature, note.author.public_key, note.is_encrypted):
        flash('Verification failed.', 'danger')
        return redirect(url_for('views.list_notes'))

    form = NoteForm(obj=note)
    decryption_form = DecryptForm()
    decrypted_content = None

    # convert shared_with list into emails separated by commas format
    email_list = note.shared_with
    if email_list:
        shared_with = ', '.join(email_list)
        form.shared_with.data = shared_with

    if request.method == 'POST':
        # when decrypt button is pressed:
        if 'decrypt' in request.form and decryption_form.validate_on_submit():
            secret_key = decryption_form.secret_key.data
            try:
                decrypted_content = decrypt(note.content, secret_key, note.nonce, note.tag).decode()
                form.content.data = decrypted_content
                form.secret_key.data = secret_key
                form.is_encrypted.data = True
                form.is_public.data = note.is_public
            except Exception:
                time.sleep(0.3)
                flash('Invalid decryption key. Please try again.', 'danger')
                return redirect(url_for('views.edit_note', note_id=note_id))

        # when save note button is pressed:
        elif 'save' in request.form:
            if not form.validate_on_submit():
                return render_template(
                    'add-note.html',
                    form=form,
                    editing=True,
                    decryption_form=decryption_form,
                    note=note,
                    decrypted_content=form.content.data  # keep decrypted content
                )

            note.title = form.title.data
            note.content = form.content.data
            note.is_encrypted = form.is_encrypted.data
            note.is_public = form.is_public.data
            note.shared_with = (
                [email.strip() for email in form.shared_with.data.split(',')]
                if form.shared_with.data else None
            )

            # encrypt note
            if note.is_encrypted:
                note.content, note.tag, note.nonce = encrypt(note.content.encode(), form.secret_key.data)

            # get encrypted private key
            encrypted_private_key = current_user.encrypted_private_key
            if not encrypted_private_key:
                flash("An error occurred.", "danger")
                return redirect(url_for('views.add_note'))

            # decrypt user's private key
            private_key = decrypt_secret(encrypted_private_key)

            # generate signature
            note.signature = generate_signature(note.content, private_key, form.is_encrypted.data)

            try:
                db.session.commit()
                flash('Note updated successfully!', 'success')
                return redirect(url_for('views.list_notes'))
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while updating the note. Please try again.', 'danger')

    return render_template('add-note.html', form=form, editing=True, decryption_form=decryption_form, note=note, decrypted_content=decrypted_content)



@views.route('/delete-note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()

    try:
        db.session.delete(note)
        db.session.commit()
        flash('Note deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the note. Please try again.', 'danger')

    return redirect(url_for('views.list_notes'))


@views.route('/notes', methods=['GET'])
@login_required
def list_notes():
    my_notes = Note.query.filter_by(user_id=current_user.id).all()

    public_notes = Note.query.filter(
        Note.is_public == True,
        Note.user_id != current_user.id,
        Note.shared_with == "null"
    ).all()

    shared_notes = Note.query.filter(Note.shared_with.contains([current_user.email])).all()

    return render_template(
        'notes.html',
        my_notes=my_notes,
        public_notes=public_notes,
        shared_notes=shared_notes
    )


@views.route('/view-note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def view_note(note_id):
    note = Note.query.filter_by(id=note_id).first_or_404()

    # verify signature
    if not verify_signature(note.content, note.signature, note.author.public_key, note.is_encrypted):
        flash('Verification failed.', 'danger')
        return redirect(url_for('views.list_notes'))

    user_has_access = (
            note.user_id == current_user.id or  # note's author
            (note.is_public and (not note.shared_with or current_user.email in note.shared_with))  # public
    )

    if not user_has_access:
        flash('You do not have access to this note.', 'danger')
        return redirect(url_for('views.list_notes'))

    form = DecryptForm()
    decrypted_content = ""
    if note.is_encrypted:
        if form.validate_on_submit():
            secret_key = request.form.get('secret_key')
            try:
                decrypted_content = decrypt(note.content, secret_key, note.nonce, note.tag).decode()
            except Exception:
                time.sleep(0.3)
                flash('Invalid decryption key. Please try again.', 'danger')
                return redirect(url_for('views.view_note', note_id=note_id))
    else:
        decrypted_content = note.content

    decrypted_content = sanitize_content(markdown.markdown(str(decrypted_content)))
    return render_template('view-note.html', note=note, content=decrypted_content, form=form)