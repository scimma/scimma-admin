from django import forms
from django.forms.forms import Form

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Field, Submit, Button, HTML, Div
from crispy_forms.bootstrap import InlineField, FormActions

class CreateCredentialForm(forms.Form):
    desc_field = forms.CharField(label='Description', widget=forms.Textarea, required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-createCredentialForm'
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'
        self.helper.form_method = 'POST'
        self.helper.layout = Layout(
            Field('desc_field', css_class='row'),
            HTML('''
                <h2>Added Permissions</h2>
                <div class="border row mb-3">
                    <table class="table" id="added_permissions">
                        <thead>
                            <th scope="col">Name</th>
                            <th scope="col">Description</th>
                            <th scope="col">Access Via</th>
                            <th scope="col">Permissions</th>
                            <th scope="col">Remove</th>
                        </thead>
                        <tbody>
                        </tbody>
                    </table>
                </div>
            '''),
            Div(
                Button('cancel', 'Cancel', css_class='btn-secondary'),
                Submit('save', 'Create', css_class='btn-primary'),
                css_class = 'd-grid gap-2 d-md-flex justify-content-md-end'
            )
        )

class ManageCredentialForm(forms.Form):
    name_field = forms.CharField(label='Username', required=False)
    desc_field = forms.CharField(label='Description', widget=forms.Textarea, required=False)

    def __init__(self, cur_username, cur_desc='', *args, **kwargs):
        super().__init__()
        self.helper = FormHelper()
        self.helper.form_id = 'id-modifyCredentialForm'
        self.helper.form_method = 'POST'
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'
        self.fields['name_field'].initial = cur_username
        self.fields['desc_field'].initial = cur_desc
        self.helper.layout = Layout(
            Field('name_field', readonly=True),
            Field('desc_field'),
            Div(
                Button('cancel', 'Cancel', css_class='btn-secondary'),
                Submit('save', 'Modify', css_class='btn-primary'),
                css_class = 'd-grid gap-2 d-md-flex justify-content-md-end'
            )
        )

class CreateTopicForm(forms.Form):
    owning_group_field = forms.CharField(label='Owning Group')
    name_field = forms.CharField(label='Name')
    desc_field = forms.CharField(label='Description', widget=forms.Textarea, required=False)
    visibility_field = forms.ChoiceField(
        choices=[
            ('public', 'Public'),
        ], widget=forms.CheckboxSelectMultiple
    )

    def __init__(self, owning_group=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-createTopicForm'
        self.helper.form_method = 'POST'
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'
        if owning_group is not None:
            self.fields['owning_group_field'].initial = owning_group
        self.helper.layout = Layout(
            Field('owning_group_field', css_class='row', readonly=True),
            Field('name_field', css_class='row'),
            Field('desc_field', css_class='row'),
            Field('visibility_field', css_class='row form-check form-switch'),
            HTML('''
                <h2>Added Groups</h2>
                <div class="border row mb-3">
                    <table class="table" id="added_groups">
                        <thead>
                            <th scope="col">Group</th>
                            <th scope="col">Permission</th>
                            <th scope="col">Remove</th>
                        </thead>
                        <tbody>
                            <tr>
                                <td>{{ owning_group }}</td>
                                <td>Owner</td>
                                <td>Cannot remove owner</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            '''),
            Div(
                Button('cancel', 'Cancel', css_class='btn-secondary'),
                Submit('submit', 'Create', css_class='btn-primary'),
                css_class = 'd-grid gap-2 d-md-flex justify-content-md-end'
            )
        )

class SelectOwnerForm(forms.Form):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-selectOwnerForm'
        self.helper.form_method = 'POST'
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'
        self.helper.layout = Layout(
            HTML(
                '''
                <div class="col-auto">
                    <label for="owner_select" class="col-form-label">Owning group</label>
                </div>
                <div class="col-auto">
                    <input class="form-control" list="datalistOptions" id="owner_select" placeholder="Type to search..." name="submit_owner">
                    <datalist id="datalistOptions">
                        {% for group in owned_groups %}
                        <option value="{{ group.group_name }}">
                        {% endfor %}
                    </datalist>
                </div>
                '''
            ),
            Div(
                Button('cancel', 'Cancel', css_class='btn-secondary'),
                Submit('submit', 'Select', css_class='btn-primary'),
                css_class = 'mt-3'
            )
        )

class ManageTopicForm(forms.Form):
    owning_group_field = forms.CharField(label='Owning Group')
    name_field = forms.CharField(label='Name')
    desc_field = forms.CharField(label='Description', widget=forms.Textarea, required=False)
    visibility_field = forms.ChoiceField(
        choices=[
            ('public', 'Public'),
        ], widget=forms.CheckboxSelectMultiple
    )

    def __init__(self, owning_group, name, description, public, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-createTopicForm'
        self.helper.form_method = 'POST'
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'
        self.fields['owning_group_field'].initial = owning_group
        self.fields['name_field'].initial = name
        self.fields['desc_field'].initial = description
        self.fields['visibility_field'].initial = public
        self.helper.layout = Layout(
            Field('owning_group_field', css_class='row', readonly=True),
            Field('name_field', css_class='row', readonly=True),
            Field('desc_field', css_class='row'),
            Field('visibility_field', css_class='row form-check form-switch'),
            Div(
                Button('cancel', 'Cancel', css_class='btn-secondary'),
                Submit('save', 'Modify', css_class='btn-primary'),
                css_class = 'd-grid gap-2 d-md-flex justify-content-md-end'
            )
        )


class CreateGroupForm(forms.Form):
    name_field = forms.CharField(label='Name')
    desc_field = forms.CharField(label='Description', required=False, widget=forms.Textarea)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-createTopicForm'
        self.helper.form_method = 'post'
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'
        self.helper.layout = Layout(
            Field('name_field', css_class='row'),
            Field('desc_field', css_class='row'),
            HTML('''
                <h2>Added Members</h2>
                <div class="border row mb-3">
                    <table class="table" id="added_members">
                        <thead>
                            <th scope="col">ID</th>
                            <th scope="col">Name</th>
                            <th scope="col">Email</th>
                            <th scope="col">Permission</th>
                            <th scope="col">Remove</th>
                        </thead>
                        <tbody>
                        </tbody>
                    </table>
                </div>
            '''),
            Div(
                Button('cancel', 'Cancel', css_class='btn-secondary'),
                Submit('save', 'Create', css_class='btn-primary'),
                css_class = 'd-grid gap-2 d-md-flex justify-content-md-end'
            )
        )

class ManageGroupMemberForm(forms.Form):
    name_field = forms.CharField(label='Name')
    desc_field = forms.CharField(label='Description', required=False, widget=forms.Textarea)

    def __init__(self, cur_name, cur_desc, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-manageGroupMemberForm'
        self.helper.form_method = 'post'
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'
        self.fields['name_field'].initial = cur_name
        self.fields['desc_field'].initial = cur_desc
        self.helper.layout = Layout(
            Field('name_field', css_class='row', readonly=True),
            Field('desc_field', css_class='row'),
            HTML('''
                <h2>Added Members</h2>
                <div class="border row mb-3">
                    <table class="table" id="added_members">
                        <thead>
                            <th scope="col">ID</th>
                            <th scope="col">Name</th>
                            <th scope="col">Email</th>
                            <th scope="col">Permission</th>
                            <th scope="col">Remove</th>
                        </thead>
                        <tbody>
                            {% for member in members %}
                            <tr scope="row">
                                <td scope="col" class="mem_id">
                                    <input type="text" class="form-control-plaintext" name="mem_id[{{ forloop.counter0 }}]" value="{{ member.id }}" readonly>
                                </td>
                                <td scope="col" class="mem_name">
                                    <input type="text" class="form-control-plaintext" name="mem_name[{{ forloop.counter0 }}]" value="{{ member.name }}" readonly>
                                </td>
                                <td scope="col" class="mem_email">
                                    <input type="text" class="form-control-plaintext" name="mem_email[{{ forloop.counter0 }}]" value="{{ member.email }}" readonly>
                                </td>
                                <td scope="col" class="mem_type">
                                    <div class="form-check form-check-inline">
                                        <input class="form-check-input" type="radio" id="perm_mem[{{ forloop.counter0 }}]" name="member_radio[{{ forloop.counter0 }}]" value="member" {% if member.status == 1 %}checked{% endif %}>
                                        <label class="form-check-label" for="perm_mem[{{ forloop.counter0 }}]">Member</label>
                                    </div>
                                    <div class="form-check form-check-inline">
                                        <input class="form-check-input" type="radio" id="perm_own[{{ forloop.counter0 }}]" name="member_radio[{{ forloop.counter0 }}]" value="owner" {% if member.status == 2 %}checked{% endif %}>
                                        <label class="form-check-label" for="perm_own[{{ forloop.counter0 }}]">Owner</label>
                                    </div>
                                </td>
                                <td scope="col" class="remove_button">
                                    <button type="button" class="btn btn-danger removeFrom">Remove</button>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            '''),
            Div(
                Button('cancel', 'Cancel', css_class='btn-secondary'),
                Submit('save', 'Create', css_class='btn-primary'),
                css_class = 'd-grid gap-2 d-md-flex justify-content-md-end'
            )
        )

class ManageGroupTopicForm(forms.Form):
    name_field = forms.CharField(label='Name')
    desc_field = forms.CharField(label='Description', required=False, widget=forms.Textarea)

    def __init__(self, cur_name, cur_desc, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_id = 'id-manageGroupTopicForm'
        self.helper.form_method = 'post'
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-8'
        self.fields['name_field'].initial = cur_name
        self.fields['desc_field'].initial = cur_desc
        self.helper.layout = Layout(
            Field('name_field', css_class='row', readonly=True),
            Field('desc_field', css_class='row'),
            Div(
                Button('cancel', 'Cancel', css_class='btn-secondary'),
                Submit('save', 'Save', css_class='btn-primary'),
                css_class = 'd-grid gap-2 d-md-flex justify-content-md-end'
            )
        )