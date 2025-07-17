"""
Unit tests for progress indicator utilities.
"""
import pytest
from unittest.mock import patch, MagicMock
import sys
import time

from surin.utils.progress import (
    ProgressIndicator, progress_bar, progress_map, TQDM_AVAILABLE
)


class TestProgressIndicator:
    """Test progress indicator functionality."""

    @patch('sys.stderr')
    def test_init(self, mock_stderr):
        """Test initialization."""
        progress = ProgressIndicator(total=100, desc="Processing", disable=False, unit="items")
        
        assert progress.total == 100
        assert progress.desc == "Processing"
        assert progress.disable is False
        assert progress.unit == "items"
        assert progress.current == 0
        assert progress.start_time is None
        assert progress.tqdm_instance is None

    @patch('time.time')
    @patch('sys.stderr')
    def test_start_with_tqdm(self, mock_stderr, mock_time):
        """Test start with tqdm available."""
        if not TQDM_AVAILABLE:
            pytest.skip("tqdm not available")
        
        mock_time.return_value = 100.0
        
        with patch('surin.utils.progress.tqdm') as mock_tqdm:
            mock_tqdm_instance = MagicMock()
            mock_tqdm.return_value = mock_tqdm_instance
            
            progress = ProgressIndicator(total=100, desc="Processing")
            progress.start()
            
            assert progress.start_time == 100.0
            assert progress.tqdm_instance == mock_tqdm_instance
            mock_tqdm.assert_called_once_with(
                total=100,
                desc="Processing",
                unit="it",
                file=sys.stderr
            )

    @patch('time.time')
    @patch('sys.stderr')
    @patch('builtins.print')
    def test_start_without_tqdm(self, mock_print, mock_stderr, mock_time):
        """Test start without tqdm."""
        mock_time.return_value = 100.0
        
        with patch('surin.utils.progress.TQDM_AVAILABLE', False):
            progress = ProgressIndicator(total=100, desc="Processing")
            progress.start()
            
            assert progress.start_time == 100.0
            assert progress.tqdm_instance is None
            mock_print.assert_called_once()

    @patch('sys.stderr')
    def test_update_with_tqdm(self, mock_stderr):
        """Test update with tqdm available."""
        if not TQDM_AVAILABLE:
            pytest.skip("tqdm not available")
        
        with patch('surin.utils.progress.tqdm') as mock_tqdm:
            mock_tqdm_instance = MagicMock()
            mock_tqdm.return_value = mock_tqdm_instance
            
            progress = ProgressIndicator(total=100, desc="Processing")
            progress.start()
            progress.update(5)
            
            assert progress.current == 5
            mock_tqdm_instance.update.assert_called_once_with(5)

    @patch('sys.stderr')
    @patch('builtins.print')
    def test_update_without_tqdm(self, mock_print, mock_stderr):
        """Test update without tqdm."""
        with patch('surin.utils.progress.TQDM_AVAILABLE', False):
            progress = ProgressIndicator(total=100, desc="Processing")
            progress.start()
            mock_print.reset_mock()  # Reset the mock after start
            
            progress.update(5)
            
            assert progress.current == 5
            mock_print.assert_called_once()

    @patch('sys.stderr')
    def test_set_description_with_tqdm(self, mock_stderr):
        """Test set_description with tqdm available."""
        if not TQDM_AVAILABLE:
            pytest.skip("tqdm not available")
        
        with patch('surin.utils.progress.tqdm') as mock_tqdm:
            mock_tqdm_instance = MagicMock()
            mock_tqdm.return_value = mock_tqdm_instance
            
            progress = ProgressIndicator(total=100, desc="Processing")
            progress.start()
            progress.set_description("New description")
            
            assert progress.desc == "New description"
            mock_tqdm_instance.set_description.assert_called_once_with("New description")

    @patch('sys.stderr')
    @patch('builtins.print')
    def test_set_description_without_tqdm(self, mock_print, mock_stderr):
        """Test set_description without tqdm."""
        with patch('surin.utils.progress.TQDM_AVAILABLE', False):
            progress = ProgressIndicator(total=100, desc="Processing")
            progress.start()
            mock_print.reset_mock()  # Reset the mock after start
            
            progress.set_description("New description")
            
            assert progress.desc == "New description"
            mock_print.assert_called_once()

    @patch('sys.stderr')
    def test_close_with_tqdm(self, mock_stderr):
        """Test close with tqdm available."""
        if not TQDM_AVAILABLE:
            pytest.skip("tqdm not available")
        
        with patch('surin.utils.progress.tqdm') as mock_tqdm:
            mock_tqdm_instance = MagicMock()
            mock_tqdm.return_value = mock_tqdm_instance
            
            progress = ProgressIndicator(total=100, desc="Processing")
            progress.start()
            progress.close()
            
            mock_tqdm_instance.close.assert_called_once()

    @patch('time.time')
    @patch('sys.stderr')
    @patch('builtins.print')
    def test_close_without_tqdm(self, mock_print, mock_stderr, mock_time):
        """Test close without tqdm."""
        mock_time.side_effect = [100.0, 105.0]  # Start time, end time
        
        with patch('surin.utils.progress.TQDM_AVAILABLE', False):
            progress = ProgressIndicator(total=100, desc="Processing")
            progress.start()
            mock_print.reset_mock()  # Reset the mock after start
            
            progress.close()
            
            mock_print.assert_called_once()

    @patch('sys.stderr')
    def test_disabled_progress(self, mock_stderr):
        """Test disabled progress indicator."""
        progress = ProgressIndicator(total=100, desc="Processing", disable=True)
        
        # These should all be no-ops when disabled
        progress.start()
        progress.update(5)
        progress.set_description("New description")
        progress.close()
        
        assert progress.current == 0
        assert progress.start_time is None


class TestProgressContextManager:
    """Test progress context manager."""

    @patch('surin.utils.progress.ProgressIndicator')
    def test_progress_bar(self, mock_progress_indicator):
        """Test progress_bar context manager."""
        mock_instance = MagicMock()
        mock_progress_indicator.return_value = mock_instance
        
        with progress_bar(total=100, desc="Processing", disable=False, unit="items") as progress:
            progress.update(50)
        
        mock_progress_indicator.assert_called_once_with(100, "Processing", False, "items")
        mock_instance.start.assert_called_once()
        mock_instance.update.assert_called_once_with(50)
        mock_instance.close.assert_called_once()

    @patch('surin.utils.progress.progress_bar')
    def test_progress_map(self, mock_progress_bar):
        """Test progress_map function."""
        mock_context = MagicMock()
        mock_progress = MagicMock()
        mock_context.__enter__.return_value = mock_progress
        mock_progress_bar.return_value = mock_context
        
        # Define test function
        def square(x):
            return x * x
        
        # Test progress_map
        result = progress_map(square, [1, 2, 3, 4, 5], desc="Squaring", disable=True)
        
        assert result == [1, 4, 9, 16, 25]
        mock_progress_bar.assert_called_once_with(
            total=5, desc="Squaring", disable=True, unit="it"
        )
        assert mock_progress.update.call_count == 5