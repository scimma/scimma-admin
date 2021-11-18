$(document).ready(function() {
    index_cred_table = $('#cred-table').DataTable({
        'info': false,
        'columns': [
            null,
            {'searchable': false},
            null,
            {'searchable': false, 'orderable': false},
            {'searchable': false, 'orderable': false},
            {'searchable': false, 'orderable': false},
        ]
    });
    index_topic_table = $('#topic-table').DataTable({
        'info': false,
        'columns': [
            null,
            null,
            {'searchable': false},
            {'searchable': false, 'orderable': false},
            {'searchable': false, 'orderable': false},
        ]
    });
    index_group_table = $('#group-table').DataTable({
        'info': false,
        'columns': [
            null,
            {'searchable': false},
            {'searchable': false, 'orderable': false},
            {'searchable': false, 'orderable': false},
        ]
    });
});