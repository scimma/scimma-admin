String.prototype.format = function () {
    var i = 0, args = arguments;
    return this.replace(/{}/g, function () {
      return typeof args[i] != 'undefined' ? args[i++] : '';
    });
  };
  
  $(document).ready(function() {
    line_count = $('#added_permissions > tbody > tr').length;
  
    avail_table = $('#avail_members').DataTable({
        'info': false,
        'columns': [
            null,
            null,
            {'searchable': false},
            {'searchable': false, 'orderable': false}
        ]
    });
    
    $('#avail_members').on('click', '.addToCur', function() {
        var trElem = $(this).closest("tr");
        var d = avail_table.row( trElem ).data();
        $('#id_perm_name').val(d[0]);
    });
  } );
  