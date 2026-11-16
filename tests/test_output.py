"""
Tests for output module
"""

import pytest
import os
import csv
from pathlib import Path

from plc_discovery.config import StatusCode
from plc_discovery.output import (
    CSVExporter, load_denied_addresses
)


class TestCSVExporter:
    """Tests for CSVExporter class"""
    
    def test_exporter_creates_output_dir(self, temp_output_dir):
        """Test that exporter creates output directory"""
        new_dir = os.path.join(temp_output_dir, "new_subdir")
        exporter = CSVExporter(new_dir)
        assert os.path.exists(new_dir)
    
    def test_export_discovery_results(self, temp_output_dir, sample_plc_list):
        """Test exporting discovery results"""
        exporter = CSVExporter(temp_output_dir)
        filepath = exporter.export_discovery_results(sample_plc_list)
        
        assert os.path.exists(filepath)
        assert "discovery_result_" in filepath
        assert filepath.endswith(".csv")
        
        # Verify content
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 3
        assert rows[0]["ip_address"] == "192.168.1.10"
        assert rows[0]["protocol"] == "SLMP"
        assert rows[1]["ip_address"] == "192.168.1.20"
        assert rows[2]["ip_address"] == "192.168.1.30"
    
    def test_export_discovery_results_custom_filename(self, temp_output_dir, sample_plc_list):
        """Test exporting with custom filename"""
        exporter = CSVExporter(temp_output_dir)
        filepath = exporter.export_discovery_results(
            sample_plc_list,
            filename="custom_discovery.csv"
        )
        
        assert filepath.endswith("custom_discovery.csv")
        assert os.path.exists(filepath)
    
    def test_export_plc_data(self, temp_output_dir, sample_data_points):
        """Test exporting PLC data"""
        exporter = CSVExporter(temp_output_dir)
        filepath = exporter.export_plc_data(
            sample_data_points,
            plc_ip="192.168.1.10"
        )
        
        assert os.path.exists(filepath)
        assert "plc_data_192_168_1_10" in filepath
        
        # Verify content
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 4
        assert rows[0]["address"] == "D0"
        assert rows[0]["value"] == "100"
        assert rows[0]["status"] == "OK"
        assert rows[2]["status"] == "NG_ILLEGAL_ADDR"
    
    def test_export_denied_addresses(self, temp_output_dir):
        """Test exporting denied addresses"""
        exporter = CSVExporter(temp_output_dir)
        denied = {"D100", "D101", "D102"}
        
        filepath = exporter.export_denied_addresses(
            denied,
            plc_ip="192.168.1.10"
        )
        
        assert os.path.exists(filepath)
        
        # Verify content
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 3
        addresses = {row["address"] for row in rows}
        assert addresses == denied
    
    def test_export_denied_addresses_append(self, temp_output_dir):
        """Test appending to denied addresses file"""
        exporter = CSVExporter(temp_output_dir)
        
        # First export
        exporter.export_denied_addresses(
            {"D100"},
            plc_ip="192.168.1.10",
            filename="denied.csv"
        )
        
        # Second export (append)
        filepath = exporter.export_denied_addresses(
            {"D200"},
            plc_ip="192.168.1.20",
            filename="denied.csv"
        )
        
        # Verify both entries
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 2
        ips = {row["plc_ip"] for row in rows}
        assert "192.168.1.10" in ips
        assert "192.168.1.20" in ips
    
    def test_export_summary_report(self, temp_output_dir, sample_plc_list):
        """Test exporting summary report"""
        exporter = CSVExporter(temp_output_dir)
        
        stats = {
            "192.168.1.10": {
                "total_points": 1000,
                "success_count": 990,
                "error_count": 10,
                "success_rate": "99.00%",
                "denied_addresses": 5,
            },
            "192.168.1.20": {
                "total_points": 500,
                "success_count": 450,
                "error_count": 50,
                "success_rate": "90.00%",
                "denied_addresses": 20,
            },
        }
        
        filepath = exporter.export_summary_report(sample_plc_list, stats)
        
        assert os.path.exists(filepath)
        assert "scan_summary_" in filepath
        
        # Verify content
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 3
        assert rows[0]["total_points"] == "1000"
        assert rows[0]["success_rate"] == "99.00%"


class TestLoadDeniedAddresses:
    """Tests for load_denied_addresses function"""
    
    def test_load_denied_addresses(self, temp_output_dir):
        """Test loading denied addresses from file"""
        # Create a test file
        filepath = os.path.join(temp_output_dir, "denied.csv")
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["address", "status", "last_attempt", "plc_ip"])
            writer.writeheader()
            writer.writerow({
                "address": "D100",
                "status": "NG_ILLEGAL_ADDR",
                "last_attempt": "2024-01-01 10:00:00",
                "plc_ip": "192.168.1.10"
            })
            writer.writerow({
                "address": "D101",
                "status": "NG_ILLEGAL_ADDR",
                "last_attempt": "2024-01-01 10:00:00",
                "plc_ip": "192.168.1.10"
            })
        
        denied = load_denied_addresses(filepath)
        assert len(denied) == 2
        assert "D100" in denied
        assert "D101" in denied
    
    def test_load_denied_addresses_filter_by_ip(self, temp_output_dir):
        """Test loading denied addresses filtered by IP"""
        filepath = os.path.join(temp_output_dir, "denied.csv")
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["address", "status", "last_attempt", "plc_ip"])
            writer.writeheader()
            writer.writerow({
                "address": "D100",
                "status": "NG_ILLEGAL_ADDR",
                "last_attempt": "2024-01-01",
                "plc_ip": "192.168.1.10"
            })
            writer.writerow({
                "address": "D200",
                "status": "NG_ILLEGAL_ADDR",
                "last_attempt": "2024-01-01",
                "plc_ip": "192.168.1.20"
            })
        
        denied = load_denied_addresses(filepath, plc_ip="192.168.1.10")
        assert len(denied) == 1
        assert "D100" in denied
        assert "D200" not in denied
    
    def test_load_denied_addresses_file_not_found(self, temp_output_dir):
        """Test loading from non-existent file"""
        filepath = os.path.join(temp_output_dir, "nonexistent.csv")
        denied = load_denied_addresses(filepath)
        assert len(denied) == 0

