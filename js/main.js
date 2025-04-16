// Main JavaScript file for SSH Log Analyzer

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    
    // File upload enhancements
    const fileUploadArea = document.getElementById('file-upload-area');
    const fileInput = document.getElementById('log_file');
    
    if (fileUploadArea && fileInput) {
        // Click on the upload area to trigger file input
        fileUploadArea.addEventListener('click', function() {
            fileInput.click();
        });
        
        // Display selected filename
        fileInput.addEventListener('change', function() {
            updateFileSelection(this);
        });
        
        // Drag and drop support
        fileUploadArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            this.classList.add('dragover');
        });
        
        fileUploadArea.addEventListener('dragleave', function() {
            this.classList.remove('dragover');
        });
        
        fileUploadArea.addEventListener('drop', function(e) {
            e.preventDefault();
            this.classList.remove('dragover');
            
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                updateFileSelection(fileInput);
            }
        });
    }
    
    // Display selected file name and size
    function updateFileSelection(input) {
        const fileNameDisplay = document.getElementById('selected-file-name');
        const fileSizeDisplay = document.getElementById('selected-file-size');
        
        if (input.files.length > 0) {
            const file = input.files[0];
            fileNameDisplay.textContent = file.name;
            fileSizeDisplay.textContent = formatFileSize(file.size);
            document.getElementById('file-info').classList.remove('d-none');
            document.getElementById('upload-prompt').classList.add('d-none');
        }
    }
    
    // Format file size in KB, MB, etc.
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Form submission handling with progress indication
    const analysisForm = document.getElementById('analysis-form');
    const submitButton = document.getElementById('submit-button');
    const loadingSpinner = document.getElementById('loading-spinner');
    
    if (analysisForm) {
        analysisForm.addEventListener('submit', function() {
            // Display loading state
            if (submitButton && loadingSpinner) {
                submitButton.disabled = true;
                submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Analyzing...';
                loadingSpinner.classList.remove('d-none');
            }
        });
    }
    
    // Table sorting functionality
    const sortableTables = document.querySelectorAll('.sortable-table');
    
    sortableTables.forEach(table => {
        const headers = table.querySelectorAll('th.sortable-header');
        
        headers.forEach(header => {
            header.addEventListener('click', function() {
                const index = Array.from(this.parentNode.children).indexOf(this);
                const isAsc = this.classList.contains('asc');
                
                // Remove sorting classes from all headers
                headers.forEach(h => {
                    h.classList.remove('asc', 'desc');
                });
                
                // Set new sorting direction
                this.classList.add(isAsc ? 'desc' : 'asc');
                
                // Sort the table
                sortTable(table, index, !isAsc);
            });
        });
    });
    
    function sortTable(table, column, asc) {
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        
        // Sort rows
        rows.sort((a, b) => {
            const aValue = a.children[column].textContent.trim();
            const bValue = b.children[column].textContent.trim();
            
            // Try to sort as numbers if possible
            const aNum = parseFloat(aValue);
            const bNum = parseFloat(bValue);
            
            if (!isNaN(aNum) && !isNaN(bNum)) {
                return asc ? aNum - bNum : bNum - aNum;
            }
            
            // Sort as strings
            return asc 
                ? aValue.localeCompare(bValue)
                : bValue.localeCompare(aValue);
        });
        
        // Remove existing rows
        while (tbody.firstChild) {
            tbody.removeChild(tbody.firstChild);
        }
        
        // Add sorted rows
        tbody.append(...rows);
    }
    
    // Filter input functionality
    const filterInput = document.getElementById('filter-table-input');
    
    if (filterInput) {
        filterInput.addEventListener('input', function() {
            const table = document.querySelector('.filterable-table');
            const value = this.value.toLowerCase();
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(value) ? '' : 'none';
            });
            
            // Show "no results" message if all rows are hidden
            const visibleRows = Array.from(rows).filter(row => row.style.display !== 'none');
            const noResultsRow = document.getElementById('no-results-row');
            
            if (noResultsRow) {
                if (visibleRows.length === 0 && value.length > 0) {
                    noResultsRow.classList.remove('d-none');
                } else {
                    noResultsRow.classList.add('d-none');
                }
            }
        });
    }
    
    // Copy to clipboard functionality
    const copyButtons = document.querySelectorAll('.copy-to-clipboard');
    
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy-text');
            
            navigator.clipboard.writeText(textToCopy).then(() => {
                // Show success feedback
                const originalText = this.innerHTML;
                this.innerHTML = '<i class="bi bi-check-circle"></i> Copied!';
                
                setTimeout(() => {
                    this.innerHTML = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Could not copy text: ', err);
            });
        });
    });
    
    // Date range validation
    const fromDateInput = document.getElementById('from_date');
    const toDateInput = document.getElementById('to_date');
    
    if (fromDateInput && toDateInput) {
        toDateInput.addEventListener('change', function() {
            if (fromDateInput.value && this.value) {
                const fromDate = new Date(fromDateInput.value);
                const toDate = new Date(this.value);
                
                if (toDate < fromDate) {
                    this.setCustomValidity('End date must be after start date');
                } else {
                    this.setCustomValidity('');
                }
            }
        });
        
        fromDateInput.addEventListener('change', function() {
            if (toDateInput.value) {
                const event = new Event('change');
                toDateInput.dispatchEvent(event);
            }
        });
    }
});

// Function to toggle theme (light/dark)
function toggleTheme() {
    const htmlElement = document.documentElement;
    const currentTheme = htmlElement.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    htmlElement.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    // Update theme toggle button text
    const themeToggleButton = document.getElementById('theme-toggle');
    if (themeToggleButton) {
        if (newTheme === 'dark') {
            themeToggleButton.innerHTML = '<i class="bi bi-sun"></i> Light Mode';
        } else {
            themeToggleButton.innerHTML = '<i class="bi bi-moon"></i> Dark Mode';
        }
    }
}

// Export functionality
function exportTableToCSV(tableId, filename) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const rows = table.querySelectorAll('tr');
    let csv = [];
    
    for (const row of rows) {
        const cells = row.querySelectorAll('td, th');
        const rowData = Array.from(cells).map(cell => {
            // Replace commas and quotes in the data to avoid CSV issues
            return '"' + cell.textContent.replace(/"/g, '""') + '"';
        });
        csv.push(rowData.join(','));
    }
    
    // Create a CSV file and download it
    const csvContent = csv.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.display = 'none';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}