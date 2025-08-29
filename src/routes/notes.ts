import { Router } from 'express';
import { NotesController } from '../controllers/notesController';
import { validateNote } from '../middleware/validation';
import { authenticateToken } from '../middleware/auth';

const router = Router();
const notesController = new NotesController();

// All routes are protected
router.use(authenticateToken);

// Notes CRUD routes
router.post('/create', validateNote, notesController.createNote);
router.get('/', notesController.getNotes);
router.get('/:id', notesController.getNoteById);
router.put('/:id', notesController.updateNote);
router.delete('/:id', notesController.deleteNote).patch('/:id', notesController.updatePinToggleNote);
router.delete('/', notesController.deleteAllNotes);

export { router as notesRoutes };
