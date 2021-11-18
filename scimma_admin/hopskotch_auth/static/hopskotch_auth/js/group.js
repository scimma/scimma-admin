String.prototype.format = function () {
    var i = 0, args = arguments;
    return this.replace(/{}/g, function () {
      return typeof args[i] != 'undefined' ? args[i++] : '';
    });
  };

$(document).ready(function() {
    line_count = 0;
    avail_members = $('#avail_members').DataTable({
      'info': false,
      'columns': [
        null,
        null,
        null,
        {'searchable': false, 'orderable': false},
      ]
    });

    function create_line(idx, id, name, email)
    {
      return '<tr scope="row">\
              <td scope="col" class="mem_id"><input type="text" class="form-control-plaintext" name="mem_id[{}]" value="{}" readonly></td>\
              <td scope="col" class="mem_name"><input type="text" class="form-control-plaintext" name="mem_name[{}]" value="{}" readonly></td>\
              <td scope="col" class="mem_email"><input type="text" class="form-control-plaintext" name="mem_email[{}]" value="{}" readonly></td>\
              <td scope="col" class="mem_type"><div class="form-check form-check-inline"><input class="form-check-input" type="radio" id="perm_mem[{}]" name="member_radio[{}]" value="member" checked><label class="form-check-label" for="perm_mem[{}]">Member</label></div><div class="form-check form-check-inline"><input class="form-check-input" type="radio" id="perm_own[{}]" name="member_radio[{}]" value="owner"><label class="form-check-label" for="perm_own[{}]">Owner</label></div></td>\
              <td scope="col" class="remove_button"><button type="button" class="btn btn-danger removeFrom">Remove</button></td>\
              </tr>'.format(idx, id, idx, name, idx, email, idx, idx, idx, idx, idx, idx)
    }

    $('#avail_members').on('click', '.addToCur', function() {
      var trElem = $(this).closest('tr');
      var d = avail_members.row(trElem).data();
      var row = avail_members.row(trElem);
      row.remove().draw();
      $('#added_members > tbody:last-child').append(create_line(line_count, d[0], d[1], d[2]));
      line_count = line_count + 1;
    })

    $('#added_members').on('click', '.removeFrom', function() {
      var trElem = $(this).closest('tr');
      var member_id = trElem.children('td.mem_id').find('input').val();
      var member_name = trElem.children('td.mem_name').find('input').val();
      var member_email = trElem.children('td.mem_email').find('input').val();
      avail_members.row.add(
        [
          member_id,
          member_name,
          member_email,
          '<button type="button" class="btn btn-primary addToCur">Add</button>',
        ]
      ).draw()
      trElem.remove();
    })
});