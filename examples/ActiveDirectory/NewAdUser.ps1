C:\> import-csv .\newusers.csv |
select-object -property *,
@{name='samAccountName';expression={$_.login}},
@{label='Name';expression={$_.login}},
@{n='Department';e={$_.Dept}} | New-AzADUser