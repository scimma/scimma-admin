String.prototype.format = function () {
    var i = 0, args = arguments;
    return this.replace(/{}/g, function () {
      return typeof args[i] != 'undefined' ? args[i++] : '';
    });
  };

$(document).ready(function() {
    line_count = $('#added_permissions > tbody > tr').length;

    avail_table = $('#avail_table').DataTable({
        'info': false,
        'columns': [
            null,
            null,
            {'searchable': false},
            {'searchable': false, 'orderable': false}
        ]
    });

    function create_line(idx, group_name, description, access_field)
    {
        return '<tr scope="row">\
                <td class="topic_name"><input type="text" class="form-control-plaintext" name="group_name[{}]" value="{}" readonly></td>\
                <td class="topic_desc"><input type="text" class="form-control-plaintext" name="desc_field[{}]" value="{}" readonly></td>\
                <td class="topic_access">{}</td>\
                <td class="perm_fields"><div class="form-check form-check-inline"><input class="form-check-input" type="checkbox" id="perm_1[{}]" name="read_[{}]" value="read_perm"><label class="form-check-label" for="perm_1[{}]">Read</label></div><div class="form-check form-check-inline"><input class="form-check-input" type="checkbox" id="perm_[{}]" name="write_[{}]" value="write_perm"><label class="form-check-label" for="perm_2[{}]">Write</label></div></td>\
                <td scope="col" class="remove_button"><button type="button" class="btn btn-danger removeFrom objectModifier">Remove</button></td>\
                </tr>'.format(idx, group_name, idx, description, access_field, idx, idx, idx, idx, idx, idx)
    }
    
    $('#avail_table').on('click', '.addToCur', function() {
        var trElem = $(this).closest("tr");
        var d = avail_table.row( trElem ).data();
        var row = avail_table.row(trElem);
        row.remove().draw();
        $('#added_permissions > tbody:last-child').append(create_line(line_count, d[0], d[1], d[2]));
        line_count = line_count + 1;

    })

    $('#added_permissions').on('click', '.removeFrom', function() {
        var trElem = $(this).closest('tr');
        var topic_name = trElem.children('td.topic_name').find('input').val();
        var topic_desc = trElem.children('td.topic_desc').find('input').val();
        var topic_access = trElem.children('td.topic_access').text();
        avail_table.row.add(
            [
                topic_name,
                topic_desc,
                topic_access,
                '<button type="button" class="btn btn-primary addToCur objectModifier">Add</button>'
            ]
        ).draw();
        trElem.remove();
    });
} );
