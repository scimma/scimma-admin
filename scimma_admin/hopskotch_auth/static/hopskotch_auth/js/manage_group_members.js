String.prototype.format = function () {
    var i = 0, args = arguments;
    return this.replace(/{}/g, function () {
      return typeof args[i] != 'undefined' ? args[i++] : '';
    });
  };
  
  function getCookie(c_name)
  {
    if (document.cookie.length > 0)
    {
        c_start = document.cookie.indexOf(c_name + "=");
        if (c_start != -1)
        {
            c_start = c_start + c_name.length + 1;
            c_end = document.cookie.indexOf(";", c_start);
            if (c_end == -1) c_end = document.cookie.length;
            return unescape(document.cookie.substring(c_start,c_end));
        }
    }
    return "";
  }
  
  $(document).ready(function() {
    function onAddMemberCallback() {
        var trElem = $(this).closest('tr');
        var username = trElem.find('td.add_id').text();
        var groupname = $('#name_field').val();
        addMember(groupname, username, trElem);
    }

    function onRemoveMemberCallback() {
        var trElem = $(this).closest('tr');
        var username = trElem.find('td.mem_id').text();
        var groupname = $('#name_field').val();
        removeMember(groupname, username, trElem);
    }

    function addMember(groupname, username, trElem) {
        gam_link = $('#gam_url').data().link;
        $.ajax({
            url: gam_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                groupname: groupname,
                username: username
            },
            success: function (data, textStatus, jqXHR){
                trElem.remove();
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
            }
        });
    }

    function removeMember(groupname, username, trElem) {
        grm_link = $('#grm_url').data().link;
        $.ajax({
            url: grm_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                groupname: groupname,
                username: username
            },
            success: function (data, textStatus, jqXHR){
                trElem.remove();
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
            }
        });
    }

    $('body').on('click', '.addToCur', onAddMemberCallback);
    $('body').on('click', '.removeFrom', onRemoveMemberCallback);
  });