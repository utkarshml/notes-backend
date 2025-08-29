import { Response } from 'express';
import mongoose from 'mongoose';
import { Note } from '../models/Note';
import { AuthenticatedRequest, ApiResponse } from '../types';

export class NotesController {
  // Create a new note
  async createNote(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const { title, content, tags, isPinned } = req.body;
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      const note = await Note.create({
        userId: new mongoose.Types.ObjectId(userId),
        title: title.trim(),
        content: content.trim(),
        tags: tags || [],
        isPinned: isPinned || false
      });

      res.status(201).json({
        success: true,
        message: 'Note created successfully',
        data: { note }
      });
    } catch (error) {
      console.error('Create note error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Get all notes for the authenticated user
  async getNotes(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const userId = req.user?.userId;
      const { page = '1', limit = '10', search, tags, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      // Build filter
      const filter: any = { userId: new mongoose.Types.ObjectId(userId) };

      // Search functionality
      if (search && typeof search === 'string') {
        filter.$or = [
          { title: { $regex: search, $options: 'i' } },
          { content: { $regex: search, $options: 'i' } }
        ];
      }

      // Tags filter
      if (tags && typeof tags === 'string') {
        const tagsArray = tags.split(',').map(tag => tag.trim());
        filter.tags = { $in: tagsArray };
      }

      // Pagination
      const pageNum = Math.max(1, parseInt(page as string));
      const limitNum = Math.min(50, Math.max(1, parseInt(limit as string)));
      const skip = (pageNum - 1) * limitNum;

      // Sort
      const sortField = typeof sortBy === 'string' ? sortBy : 'createdAt';
      const sortDir = sortOrder === 'asc' ? 1 : -1;
      const sort: any = {};
      
      // Special sorting for pinned notes
      if (sortField === 'createdAt') {
        sort.isPinned = -1; // Pinned notes first
        sort.createdAt = sortDir;
      } else {
        sort[sortField] = sortDir;
      }

      // Execute query
      const [notes, totalCount] = await Promise.all([
        Note.find(filter)
          .sort(sort)
          .skip(skip)
          .limit(limitNum)
          .select('-__v'),
        Note.countDocuments(filter)
      ]);

      const totalPages = Math.ceil(totalCount / limitNum);

      res.status(200).json({
        success: true,
        message: 'Notes retrieved successfully',
        data: {
          notes,
          pagination: {
            currentPage: pageNum,
            totalPages,
            totalCount,
            hasNextPage: pageNum < totalPages,
            hasPrevPage: pageNum > 1
          }
        }
      });
    } catch (error) {
      console.error('Get notes error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Get a specific note by ID
  async getNoteById(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      if (!mongoose.Types.ObjectId.isValid(id)) {
        res.status(400).json({
          success: false,
          message: 'Invalid note ID',
          error: 'Invalid ID format'
        });
        return;
      }

      const note = await Note.findOne({
        _id: new mongoose.Types.ObjectId(id),
        userId: new mongoose.Types.ObjectId(userId)
      }).select('-__v');

      if (!note) {
        res.status(404).json({
          success: false,
          message: 'Note not found',
          error: 'Note not found'
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Note retrieved successfully',
        data: { note }
      });
    } catch (error) {
      console.error('Get note by ID error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Update a note
  async updateNote(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const { id } = req.params;
      const { title, content, tags, isPinned } = req.body;
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      if (!mongoose.Types.ObjectId.isValid(id)) {
        res.status(400).json({
          success: false,
          message: 'Invalid note ID',
          error: 'Invalid ID format'
        });
        return;
      }

      const updateData: any = {};
      if (title !== undefined) updateData.title = title.trim();
      if (content !== undefined) updateData.content = content.trim();
      if (tags !== undefined) updateData.tags = tags;
      if (isPinned !== undefined) updateData.isPinned = isPinned;

      const note = await Note.findOneAndUpdate(
        {
          _id: new mongoose.Types.ObjectId(id),
          userId: new mongoose.Types.ObjectId(userId)
        },
        updateData,
        { new: true, runValidators: true }
      ).select('-__v');

      if (!note) {
        res.status(404).json({
          success: false,
          message: 'Note not found',
          error: 'Note not found'
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Note updated successfully',
        data: { note }
      });
    } catch (error) {
      console.error('Update note error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Delete a note
  async deleteNote(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      if (!mongoose.Types.ObjectId.isValid(id)) {
        res.status(400).json({
          success: false,
          message: 'Invalid note ID',
          error: 'Invalid ID format'
        });
        return;
      }

      const note = await Note.findOneAndDelete({
        _id: new mongoose.Types.ObjectId(id),
        userId: new mongoose.Types.ObjectId(userId)
      });

      if (!note) {
        res.status(404).json({
          success: false,
          message: 'Note not found',
          error: 'Note not found'
        });
        return;
      }

      res.status(200).json({
        success: true,
        message: 'Note deleted successfully',
        data: { deletedNoteId: id }
      });
    } catch (error) {
      console.error('Delete note error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  // Delete all notes for user
  async deleteAllNotes(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
    try {
      const userId = req.user?.userId;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated',
          error: 'Authentication required'
        });
        return;
      }

      const result = await Note.deleteMany({
        userId: new mongoose.Types.ObjectId(userId)
      });

      res.status(200).json({
        success: true,
        message: `${result.deletedCount} notes deleted successfully`,
        data: { deletedCount: result.deletedCount }
      });
    } catch (error) {
      console.error('Delete all notes error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
// Update Pin Toggle Note
  async updatePinToggleNote(req: AuthenticatedRequest, res: Response<ApiResponse>): Promise<void> {
  try {
    const { id } = req.params;
    const userId = req.user?.userId;

    if (!userId) {
      res.status(401).json({
        success: false,
        message: 'User not authenticated',
        error: 'Authentication required'
      });
      return;
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      res.status(400).json({
        success: false,
        message: 'Invalid note ID',
        error: 'Invalid ID format'
      });
      return;
    }

    const note = await Note.findOne(
      {
        _id: new mongoose.Types.ObjectId(id),
        userId: new mongoose.Types.ObjectId(userId)
      }
    ).select('-__v');

    if (!note) {
      res.status(404).json({
        success: false,
        message: 'Note not found',
        error: 'Note not found'
      });
      return;
    }

    note.isPinned = !note.isPinned;
    await note.save();

    res.status(200).json({
      success: true,
      message: 'Note updated successfully',
      data: { note }
    });
  } catch (error) {
    console.error('Update note error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  } 
}


}


