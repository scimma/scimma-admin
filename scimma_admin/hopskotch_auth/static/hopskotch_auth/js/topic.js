String.prototype.format = function () {
    var i = 0, args = arguments;
    return this.replace(/{}/g, function () {
      return typeof args[i] != 'undefined' ? args[i++] : '';
    });
  };

$(document).ready(function() {
    line_count = 0;
    $('#owning_group').modal('toggle');

    $('#id-selectOwnerForm #submit-id-cancel').click( function(event) {
        event.preventDefault();
        owner_select = $('#owner_select');
        select_field = owner_select.find('#owner_select')
        select_button = owner_select.find('#submit-id-cancel');
        owner_name = owner_select.val();
        if(owner_name == '')
        {
            return;
        }
        $('#owning_group').modal('toggle');
        $('#id_owning_group_field').val(owner_name)
    });

    avail_table = $('#avail_table').DataTable({
        'info': false,
        'columns': [
            null,
            {'searchable': false, 'orderable': false}
        ]
    });

    function create_line(idx, group_name)
    {
        return '<tr scope="row">\
                <td scope="col" class="group_name"><input type="text" class="form-control-plaintext" name="group_name[{}]" value="{}" readonly></td>\
                <td scope="col" class="perm_fields"><div class="form-check form-check-inline"><input class="form-check-input" type="checkbox" id="perm_1[{}]" name="read_[{}]" value="read_perm"><label class="form-check-label" for="perm_1[{}]">Read</label></div><div class="form-check form-check-inline"><input class="form-check-input" type="checkbox" id="perm_[{}]" name="write_[{}]" value="write_perm"><label class="form-check-label" for="perm_2[{}]">Write</label></div></td>\
                <td scope="col" class="remove_button"><button type="button" class="btn btn-danger removeFrom">Remove</button></td>\
                </tr>'.format(idx, group_name, idx, idx, idx, idx, idx, idx)
    }

    $('#avail_table').on('click', '.addToCur', function() {
        var trElem = $(this).closest('tr');
        var d = avail_table.row(trElem).data();
        var row = avail_table.row(trElem);
        row.remove().draw();
        $('#added_groups > tbody:last-child').append(create_line(line_count, d[0]));
        line_count = line_count + 1;
    });

    $('#added_groups').on('click', '.removeFrom', function() {
        var trElem = $(this).closest('tr');
        var group_name = trElem.children('td.group_name').find('input').val();
        avail_table.row.add(
            [
                group_name,
                '<button type="button" class="btn btn-primary addToCur">Add</button>'
            ]
        ).draw();
        trElem.remove();
    });

});